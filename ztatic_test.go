package ztatic

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/log"
	"ztatic-go-framework/security/audit"
)

func TestNewSecure(t *testing.T) {
	app := NewSecure()
	if app == nil || app.Echo == nil {
		t.Fatalf("expected non-nil app and echo instance")
	}

	if app.Validator == nil {
		t.Errorf("expected StructValidator to be set on secure engine")
	}

	app.GET("/ping", func(c *Context) error {
		return c.String(http.StatusOK, "pong")
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", rec.Code)
	}

	// Verify default Security Headers applied by NewSecure
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected X-Content-Type-Options header to be nosniff")
	}
}

func TestNewWithConfig_CustomSecurity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Security.EnableHeaders = false
	cfg.Security.EnableWAF = false
	cfg.Security.EnableCSRF = false
	cfg.Security.EnableRateLimiter = false

	app := NewWithConfig(cfg)
	if app == nil {
		t.Fatalf("expected non-nil app")
	}

	app.GET("/test", func(c *Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?id=1%20UNION%20SELECT%201", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	// WAF is disabled, so SQLi URI should not be blocked by WAF
	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 when WAF is disabled, got %d", rec.Code)
	}
	if rec.Header().Get("X-Content-Type-Options") != "" {
		t.Errorf("expected security headers to be omitted when disabled")
	}
}

func TestNew_LeanEngine(t *testing.T) {
	app := New()
	if app == nil || app.Echo == nil {
		t.Fatalf("expected non-nil app")
	}

	app.GET("/raw", func(c *Context) error {
		return c.String(http.StatusOK, "raw response")
	})

	req := httptest.NewRequest(http.MethodGet, "/raw", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", rec.Code)
	}
	if rec.Body.String() != "raw response" {
		t.Errorf("expected body 'raw response', got %q", rec.Body.String())
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.Security.EnableHeaders || !cfg.Security.EnableWAF || !cfg.Security.EnableCSRF || !cfg.Security.EnableRateLimiter || !cfg.Security.EnableAudit {
		t.Errorf("expected default config to enable all web security modules including audit")
	}
}

func TestNewSecure_AuditLogger(t *testing.T) {
	app := NewSecure()
	if app.AuditLogger() == nil {
		t.Errorf("expected AuditLogger to be initialized by NewSecure")
	}
}

func TestEngine_UseAudit_Integration(t *testing.T) {
	app := New()
	memSink := audit.NewMemorySink(10)
	auditLogger := audit.NewSyncLogger(audit.NewJSONFormatter(false), memSink, false)

	cfg := audit.DefaultAuditConfig()
	cfg.Logger = auditLogger
	app.UseAudit(cfg)

	app.POST("/items", func(c *Context) error {
		AuditRecord(c, "inventory.item.create", "item", "item_42")
		return c.String(http.StatusCreated, "item created")
	})

	req := httptest.NewRequest(http.MethodPost, "/items", nil)
	req.Header.Set("X-User-ID", "inventory_clerk")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", rec.Code)
	}

	if memSink.Len() != 1 {
		t.Fatalf("expected 1 audit entry recorded via Engine.UseAudit, got %d", memSink.Len())
	}

	entry := memSink.Last()
	if entry.Action != "inventory.item.create" {
		t.Errorf("expected action 'inventory.item.create', got %s", entry.Action)
	}
	if entry.Target.ID != "item_42" || entry.Actor.ID != "inventory_clerk" {
		t.Errorf("target or actor incorrect: %+v, %+v", entry.Target, entry.Actor)
	}
}

func TestNewSecure_StructuredLoggingIntegration(t *testing.T) {
	cfg := DefaultConfig()
	var buf bytes.Buffer
	cfg.Log.Output = &buf
	cfg.Log.Format = log.FormatJSON

	app := NewWithConfig(cfg)
	if app.Echo.Logger == nil {
		t.Fatalf("expected structured logger to be initialized")
	}

	if app.LogLevel() != log.LevelInfo {
		t.Errorf("expected initial log level INFO, got %v", app.LogLevel())
	}

	// Test dynamic level adjustment on the engine
	app.SetLogLevel(log.LevelDebug)
	if app.LogLevel() != log.LevelDebug {
		t.Errorf("expected adjusted log level DEBUG, got %v", app.LogLevel())
	}

	app.GET("/users/:id", func(c *Context) error {
		logger := LogFromContext(c)
		logger.Info("retrieving user profile", "user_id", c.Param("id"))
		return c.JSON(http.StatusOK, Map{"id": c.Param("id"), "name": "Alice"})
	})

	req := httptest.NewRequest(http.MethodGet, "/users/42", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	reqID := rec.Header().Get(echo.HeaderXRequestID)
	if reqID == "" {
		t.Errorf("expected X-Request-ID to be set in response header")
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "retrieving user profile") {
		t.Errorf("expected handler log in output, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, "HTTP request") {
		t.Errorf("expected request logger entry in output, got: %s", logOutput)
	}
	if !strings.Contains(logOutput, reqID) {
		t.Errorf("expected request ID %s in log output, got: %s", reqID, logOutput)
	}
}

func TestNewSecure_StandardizedErrors_NotFound(t *testing.T) {
	app := NewSecure()

	app.GET("/api/products/:id", func(c *Context) error {
		return ErrNotFound("product 999 does not exist")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/products/999", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	errMap, ok := body["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'error' object in JSON: %s", rec.Body.String())
	}

	if errMap["code"] != "NOT_FOUND" {
		t.Errorf("expected code NOT_FOUND, got %v", errMap["code"])
	}
	if errMap["message"] != "product 999 does not exist" {
		t.Errorf("expected message, got %v", errMap["message"])
	}
	if errMap["request_id"] == nil || errMap["request_id"] == "" {
		t.Errorf("expected request_id in error envelope")
	}
}

func TestNewSecure_StandardizedErrors_Validation(t *testing.T) {
	app := NewSecure()

	type CreateUserInput struct {
		Username string `json:"username" validate:"required,min=4"`
		Email    string `json:"email" validate:"required,email"`
	}

	app.POST("/api/users", func(c *Context) error {
		var input CreateUserInput
		input.Username = "abc"          // too short (< 4)
		input.Email = "not-an-email"    // invalid email
		if err := c.Validate(&input); err != nil {
			return err
		}
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	errMap := body["error"].(map[string]any)
	if errMap["code"] != "VALIDATION_FAILED" {
		t.Errorf("expected code VALIDATION_FAILED, got %v", errMap["code"])
	}

	details, ok := errMap["details"].([]any)
	if !ok || len(details) != 2 {
		t.Fatalf("expected 2 details violations, got %v", details)
	}
}

func TestNewSecure_StandardizedErrors_ProductionSanitization(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Error.ExposeInternalErrors = false
	cfg.Error.FallbackMessage = "Secure system error occurred"
	app := NewWithConfig(cfg)

	app.GET("/api/sensitive", func(c *Context) error {
		sensitiveDBErr := errors.New("FATAL: password authentication failed for user postgres")
		return ErrInternal("database error").WithInternal(sensitiveDBErr)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/sensitive", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON: %v", err)
	}

	errMap := body["error"].(map[string]any)
	msg := errMap["message"].(string)

	if !strings.Contains(msg, "Secure system error occurred") {
		t.Errorf("expected fallback message, got: %s", msg)
	}
	if strings.Contains(rec.Body.String(), "password authentication failed") {
		t.Errorf("leaked sensitive database credentials in production error response!")
	}
}


