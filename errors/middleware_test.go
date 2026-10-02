package errors

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestMiddleware_HTTPErrorHandler_Basic(t *testing.T) {
	e := echo.New()
	handler := NewHTTPErrorHandler(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(echo.HeaderXRequestID, "req-test-123")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Simulate handler error
	handler(c, NotFound("resource missing"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}

	var resp ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error.Code != CodeNotFound {
		t.Errorf("expected NOT_FOUND, got %s", resp.Error.Code)
	}
	if resp.Error.RequestID != "req-test-123" {
		t.Errorf("expected req-test-123, got %s", resp.Error.RequestID)
	}
}

func TestMiddleware_HTTPErrorHandler_CommittedResponseGuard(t *testing.T) {
	e := echo.New()
	handler := NewHTTPErrorHandler(DefaultConfig())

	req := httptest.NewRequest(http.MethodGet, "/committed", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// Commit response manually
	c.Response().WriteHeader(http.StatusOK)
	_, _ = c.Response().Write([]byte("already committed"))

	// Subsequent error should not overwrite committed status or corrupt stream
	handler(c, BadRequest("late error"))

	if rec.Code != http.StatusOK {
		t.Errorf("expected status to remain 200, got %d", rec.Code)
	}
	if rec.Body.String() != "already committed" {
		t.Errorf("expected body to remain unchanged, got: %s", rec.Body.String())
	}
}

func TestMiddleware_HTTPErrorHandler_OnErrorHook(t *testing.T) {
	var hookCalled bool
	var capturedCode string

	cfg := DefaultConfig()
	cfg.OnError = func(c *echo.Context, rawErr error, appErr *Error) {
		hookCalled = true
		capturedCode = appErr.Code
	}

	e := echo.New()
	handler := NewHTTPErrorHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/hook", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler(c, Forbidden("access denied"))

	if !hookCalled {
		t.Errorf("expected OnError hook to be called")
	}
	if capturedCode != CodeForbidden {
		t.Errorf("expected captured code FORBIDDEN, got %s", capturedCode)
	}
}

func TestMiddleware_HTTPErrorHandler_HeadRequest(t *testing.T) {
	e := echo.New()
	handler := NewHTTPErrorHandler(DefaultConfig())

	req := httptest.NewRequest(http.MethodHead, "/head-test", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	handler(c, NotFound("head missing"))

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty body for HEAD request, got %d bytes", rec.Body.Len())
	}
}

func TestMiddleware_RecoverMiddleware(t *testing.T) {
	e := echo.New()
	cfg := DefaultConfig()
	e.HTTPErrorHandler = NewHTTPErrorHandler(cfg)

	e.Use(RecoverMiddlewareWithConfig(cfg))
	e.GET("/panic", func(c *echo.Context) error {
		panic("database connection pool exhausted")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	// Should NOT crash or panic
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 Internal Server Error, got %d", rec.Code)
	}

	var resp ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal panic response: %v", err)
	}

	if resp.Error.Code != CodeInternal {
		t.Errorf("expected code INTERNAL_ERROR, got %s", resp.Error.Code)
	}
}

func TestMiddleware_EchoRouterIntegration(t *testing.T) {
	e := echo.New()
	e.HTTPErrorHandler = NewHTTPErrorHandler(DefaultConfig())

	e.GET("/fail", func(c *echo.Context) error {
		return errors.New("raw unhandled business error")
	})

	req := httptest.NewRequest(http.MethodGet, "/fail", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", rec.Code)
	}

	var resp ResponseEnvelope
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error.Code != CodeInternal {
		t.Errorf("expected INTERNAL_ERROR, got %s", resp.Error.Code)
	}
}
