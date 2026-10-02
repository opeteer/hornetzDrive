package errors

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestResponse_Envelope_JSON(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	appErr := NotFound("user not found").
		WithRequestID("req-9999").
		WithDetails(FieldViolation{
			Field:   "id",
			Rule:    "min",
			Message: "must be > 0",
		})

	cfg := Config{
		Format:               FormatEnvelope,
		ExposeInternalErrors: false,
	}

	err := Render(c, appErr, cfg)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}

	var resp ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal JSON envelope: %v", err)
	}

	if resp.Error == nil {
		t.Fatalf("expected non-nil Error body")
	}
	if resp.Error.Code != CodeNotFound {
		t.Errorf("expected code NOT_FOUND, got %s", resp.Error.Code)
	}
	if resp.Error.RequestID != "req-9999" {
		t.Errorf("expected req-9999, got %s", resp.Error.RequestID)
	}
	if len(resp.Error.Details) != 1 || resp.Error.Details[0].Field != "id" {
		t.Errorf("expected details with field 'id', got %+v", resp.Error.Details)
	}
}

func TestResponse_ProblemDetails_JSON(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/api/orders", nil)
	req.Header.Set("Accept", "application/problem+json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	appErr := Validation("invalid order", FieldViolation{
		Field:   "quantity",
		Rule:    "required",
		Message: "quantity is required",
	}).WithRequestID("req-prob-1")

	cfg := Config{
		Format: FormatProblemDetails,
	}

	err := Render(c, appErr, cfg)
	if err != nil {
		t.Fatalf("Render returned error: %v", err)
	}

	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422, got %d", rec.Code)
	}

	var pd ProblemDetails
	if err := json.Unmarshal(rec.Body.Bytes(), &pd); err != nil {
		t.Fatalf("failed to unmarshal ProblemDetails: %v", err)
	}

	if pd.Status != 422 {
		t.Errorf("expected status 422, got %d", pd.Status)
	}
	if pd.Type != "https://errors.ztatic.dev/codes/validation-failed" {
		t.Errorf("expected type URI, got %s", pd.Type)
	}
	if pd.Instance != "/api/orders" {
		t.Errorf("expected instance /api/orders, got %s", pd.Instance)
	}
	if len(pd.InvalidParams) != 1 {
		t.Errorf("expected 1 invalid param, got %d", len(pd.InvalidParams))
	}
}

func TestResponse_ZeroTrustProductionSanitization(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	secretInternalErr := errors.New("pq: password authentication failed for user 'postgres'")
	appErr := Internal("database crashed").
		WithInternal(secretInternalErr).
		WithStack().
		WithRequestID("req-sec-42")

	cfg := Config{
		Format:               FormatEnvelope,
		ExposeInternalErrors: false,
		FallbackMessage:      "Safe server error message",
	}

	err := Render(c, appErr, cfg)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var resp ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	// Must NOT contain internal error or stack in production!
	if resp.Error.Internal != "" {
		t.Errorf("expected internal to be redacted, got: %s", resp.Error.Internal)
	}
	if resp.Error.Stack != "" {
		t.Errorf("expected stack to be omitted in production, got: %s", resp.Error.Stack)
	}
	if !strings.Contains(resp.Error.Message, "Safe server error message") {
		t.Errorf("expected safe fallback message, got: %s", resp.Error.Message)
	}
	if !strings.Contains(resp.Error.Message, "req-sec-42") {
		t.Errorf("expected reference to request ID in safe message, got: %s", resp.Error.Message)
	}
}

func TestResponse_DevelopmentMode_IncludesDetails(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	rawErr := errors.New("raw syntax error near FROM")
	appErr := Internal("query execution failed").
		WithInternal(rawErr).
		WithStack()

	cfg := Config{
		Format:               FormatEnvelope,
		ExposeInternalErrors: true,
		EnableStackTrace:     true,
	}

	err := Render(c, appErr, cfg)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	var resp ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse json: %v", err)
	}

	if resp.Error.Internal != "raw syntax error near FROM" {
		t.Errorf("expected raw error in dev mode, got: %s", resp.Error.Internal)
	}
	if resp.Error.Stack == "" {
		t.Errorf("expected stack trace in dev mode")
	}
}

func TestResponse_HTMLContentNegotiation(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	appErr := NotFound("Page not found").WithRequestID("req-html-777")

	cfg := DefaultConfig()
	err := Render(c, appErr, cfg)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected status 404, got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "<!DOCTYPE html>") {
		t.Errorf("expected HTML doctype in response, got: %s", body)
	}
	if !strings.Contains(body, "404 - Not Found") {
		t.Errorf("expected '404 - Not Found' in HTML title, got: %s", body)
	}
	if !strings.Contains(body, "req-html-777") {
		t.Errorf("expected request id in HTML output, got: %s", body)
	}
}
