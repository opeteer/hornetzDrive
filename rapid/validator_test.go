package rapid

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	ztaticErrors "ztatic-go-framework/errors"
)

type createPostInput struct {
	Title   string `json:"title" sanitize:"trim,collapse_spaces" validate:"required,min=3" message:"required=Post title is required"`
	Slug    string `json:"slug" sanitize:"trim,lower" validate:"required,slug"`
	Content string `json:"content" sanitize:"trim,strip_html" validate:"required"`
	Email   string `json:"email" sanitize:"trim,lower" validate:"required,email"`
}

func TestBindAndValidate_EndToEnd(t *testing.T) {
	e := echo.New()
	e.Validator = NewStructValidator()

	var captured createPostInput

	e.POST("/posts", func(c *echo.Context) error {
		if err := BindAndValidate(c, &captured); err != nil {
			return err
		}
		return c.JSON(http.StatusOK, captured)
	})

	// 1. Success case: Input with whitespace, uppercase email, HTML in content
	rawJSON := `{
		"title": "   My   Awesome    Post   ",
		"slug": "   MY-AWESOME-POST   ",
		"content": "  <script>evil()</script><b>Hello world content</b>  ",
		"email": "  AUTHOR@Example.COM  "
	}`

	req := httptest.NewRequest(http.MethodPost, "/posts", bytes.NewBufferString(rawJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d, body: %s", rec.Code, rec.Body.String())
	}

	if captured.Title != "My Awesome Post" {
		t.Errorf("expected collapsed title, got '%s'", captured.Title)
	}
	if captured.Slug != "my-awesome-post" {
		t.Errorf("expected lowercase trimmed slug, got '%s'", captured.Slug)
	}
	if captured.Content != "Hello world content" {
		t.Errorf("expected stripped HTML content, got '%s'", captured.Content)
	}
	if captured.Email != "author@example.com" {
		t.Errorf("expected lowercased email, got '%s'", captured.Email)
	}

	// 2. Validation failure case: Invalid slug, missing title
	invalidJSON := `{
		"title": "  ",
		"slug": "Invalid Slug With Spaces!",
		"content": "content",
		"email": "author@example.com"
	}`

	reqFail2 := httptest.NewRequest(http.MethodPost, "/posts", bytes.NewBufferString(invalidJSON))
	reqFail2.Header.Set("Content-Type", "application/json")
	recFail2 := httptest.NewRecorder()
	c := e.NewContext(reqFail2, recFail2)
	var failInput createPostInput
	err := BindAndValidate(c, &failInput)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}

	var appErr *ztaticErrors.Error
	if !ztaticErrors.As(err, &appErr) {
		t.Fatalf("expected *errors.Error, got %T", err)
	}

	if appErr.Code != ztaticErrors.CodeValidation {
		t.Errorf("expected code VALIDATION_FAILED, got %s", appErr.Code)
	}

	violations := make(map[string]ztaticErrors.FieldViolation)
	for _, v := range appErr.Details {
		violations[v.Field] = v
	}

	if v, ok := violations["title"]; !ok || v.Message != "Post title is required" {
		t.Errorf("expected custom message for title, got %+v", v)
	}
	if _, ok := violations["slug"]; !ok {
		t.Errorf("expected slug violation")
	}
}
