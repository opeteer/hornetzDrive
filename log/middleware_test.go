package log

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

func TestRequestLogger_Success200(t *testing.T) {
	var buf bytes.Buffer
	testLogger := New(Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: false,
	})

	e := echo.New()
	e.Use(RequestLoggerWithConfig(RequestLoggerConfig{
		Logger: testLogger,
	}))

	e.GET("/ping", func(c *echo.Context) error {
		return c.String(http.StatusOK, "pong")
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	reqID := rec.Header().Get(echo.HeaderXRequestID)
	if reqID == "" {
		t.Errorf("expected X-Request-ID header to be populated")
	}

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON in log, got: %v, raw: %s", err, buf.String())
	}

	if logged["level"] != "INFO" {
		t.Errorf("expected level 'INFO', got %v", logged["level"])
	}
	if logged["status"] != float64(200) {
		t.Errorf("expected status 200, got %v", logged["status"])
	}
	if logged["route"] != "/ping" {
		t.Errorf("expected route '/ping', got %v", logged["route"])
	}
	if logged["req_id"] != reqID {
		t.Errorf("expected req_id %v, got %v", reqID, logged["req_id"])
	}
}

func TestRequestLogger_Warning404(t *testing.T) {
	var buf bytes.Buffer
	testLogger := New(Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: false,
	})

	e := echo.New()
	e.Use(RequestLoggerWithConfig(RequestLoggerConfig{
		Logger: testLogger,
	}))

	e.GET("/items/:id", func(c *echo.Context) error {
		return echo.NewHTTPError(http.StatusNotFound, "item not found")
	})

	req := httptest.NewRequest(http.MethodGet, "/items/99", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404, got %d", rec.Code)
	}

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON in log, got: %v", err)
	}

	if logged["level"] != "WARN" {
		t.Errorf("expected level 'WARN' for 404, got %v", logged["level"])
	}
	if logged["status"] != float64(404) {
		t.Errorf("expected status 404, got %v", logged["status"])
	}
}

func TestRequestLogger_Error500(t *testing.T) {
	var buf bytes.Buffer
	testLogger := New(Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: false,
	})

	e := echo.New()
	e.Use(RequestLoggerWithConfig(RequestLoggerConfig{
		Logger: testLogger,
	}))

	e.GET("/crash", func(c *echo.Context) error {
		return errors.New("database connection refused")
	})

	req := httptest.NewRequest(http.MethodGet, "/crash", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500, got %d", rec.Code)
	}

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON in log, got: %v", err)
	}

	if logged["level"] != "ERROR" {
		t.Errorf("expected level 'ERROR' for 500, got %v", logged["level"])
	}
	if logged["status"] != float64(500) {
		t.Errorf("expected status 500, got %v", logged["status"])
	}
	if logged["error"] != "database connection refused" {
		t.Errorf("expected error string to be logged, got %v", logged["error"])
	}
}

func TestRequestLogger_PanicRecovery(t *testing.T) {
	var buf bytes.Buffer
	testLogger := New(Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: false,
	})

	e := echo.New()
	// Middleware order: Recover outer, RequestLogger inner
	e.Use(middleware.Recover())
	e.Use(RequestLoggerWithConfig(RequestLoggerConfig{
		Logger: testLogger,
	}))

	e.GET("/panic", func(c *echo.Context) error {
		panic("nil pointer dereference simulation")
	})

	req := httptest.NewRequest(http.MethodGet, "/panic", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected HTTP 500 from Recover middleware, got %d", rec.Code)
	}

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON in log, got: %v, raw: %s", err, buf.String())
	}

	if logged["level"] != "ERROR" {
		t.Errorf("expected level 'ERROR' for panic, got %v", logged["level"])
	}
	if logged["panic"] != "nil pointer dereference simulation" {
		t.Errorf("expected panic details in log, got %v", logged["panic"])
	}
}

func TestRequestLogger_PreserveRequestID(t *testing.T) {
	var buf bytes.Buffer
	testLogger := New(Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: false,
	})

	e := echo.New()
	e.Use(RequestLoggerWithConfig(RequestLoggerConfig{
		Logger: testLogger,
	}))

	e.GET("/test", func(c *echo.Context) error {
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set(echo.HeaderXRequestID, "custom-req-id-1234")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Header().Get(echo.HeaderXRequestID) != "custom-req-id-1234" {
		t.Errorf("expected incoming request ID to be preserved, got %s", rec.Header().Get(echo.HeaderXRequestID))
	}

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON, got: %v", err)
	}

	if logged["req_id"] != "custom-req-id-1234" {
		t.Errorf("expected log to record req_id custom-req-id-1234, got %v", logged["req_id"])
	}
}

func TestRequestLogger_Skipper(t *testing.T) {
	var buf bytes.Buffer
	testLogger := New(Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: &buf,
	})

	e := echo.New()
	e.Use(RequestLoggerWithConfig(RequestLoggerConfig{
		Logger: testLogger,
	}))

	e.GET("/healthz", func(c *echo.Context) error {
		return c.String(http.StatusOK, "healthy")
	})
	e.GET("/dist/app.js", func(c *echo.Context) error {
		return c.String(http.StatusOK, "console.log('app');")
	})

	// 1. Healthz check should be skipped
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if buf.Len() != 0 {
		t.Errorf("expected 0 log entries for /healthz, got: %s", buf.String())
	}

	// 2. Static asset should be skipped
	buf.Reset()
	req = httptest.NewRequest(http.MethodGet, "/dist/app.js", nil)
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if buf.Len() != 0 {
		t.Errorf("expected 0 log entries for /dist/app.js, got: %s", buf.String())
	}
}

func TestRequestLogger_ContextEnrichmentInHandler(t *testing.T) {
	var buf bytes.Buffer
	testLogger := New(Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: &buf,
	})

	e := echo.New()
	e.Use(RequestLoggerWithConfig(RequestLoggerConfig{
		Logger: testLogger,
	}))

	e.POST("/orders", func(c *echo.Context) error {
		// Handler uses c.Logger() or log.FromContext(c.Request().Context())
		handlerLogger := FromContext(c.Request().Context())
		handlerLogger.Info("inside order handler", "item_count", 3)
		return c.String(http.StatusOK, "order processed")
	})

	req := httptest.NewRequest(http.MethodPost, "/orders", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	lines := bytes.Split(bytes.TrimSpace(buf.Bytes()), []byte("\n"))
	if len(lines) != 2 {
		t.Fatalf("expected 2 log lines (handler log + request log), got %d: %s", len(lines), buf.String())
	}

	var handlerLog map[string]any
	if err := json.Unmarshal(lines[0], &handlerLog); err != nil {
		t.Fatalf("expected valid JSON for handler log, got: %v", err)
	}

	// Verify handler log inherited request context attributes
	if handlerLog["msg"] != "inside order handler" {
		t.Errorf("expected handler log msg, got %v", handlerLog["msg"])
	}
	if handlerLog["item_count"] != float64(3) {
		t.Errorf("expected item_count 3, got %v", handlerLog["item_count"])
	}
	if handlerLog["req_id"] == nil || handlerLog["req_id"] == "" {
		t.Errorf("expected handler log to have inherited req_id from context")
	}
	if handlerLog["method"] != "POST" {
		t.Errorf("expected handler log to have inherited method POST")
	}
}
