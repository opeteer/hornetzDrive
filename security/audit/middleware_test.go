package audit

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/security/privacy"
)

func setupTestEcho(cfg AuditConfig) (*echo.Echo, *MemorySink) {
	e := echo.New()
	memSink := NewMemorySink(50)
	cfg.Logger = NewSyncLogger(NewJSONFormatter(false), memSink, false)
	e.Use(AuditWithConfig(cfg))
	return e, memSink
}

func TestAuditMiddleware_MutatingRequestsRecorded(t *testing.T) {
	cfg := DefaultAuditConfig()
	e, memSink := setupTestEcho(cfg)

	e.POST("/api/users", func(c *echo.Context) error {
		return c.String(http.StatusCreated, "user created")
	})
	e.GET("/api/users", func(c *echo.Context) error {
		return c.String(http.StatusOK, "list users")
	})

	// 1. POST request should be logged by DefaultAuditPolicy
	req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	req.Header.Set("X-User-ID", "admin_1")
	req.Header.Set("X-User-Role", "superadmin")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", rec.Code)
	}

	if memSink.Len() != 1 {
		t.Fatalf("expected 1 audit entry for POST, got %d", memSink.Len())
	}

	entry := memSink.Last()
	if entry.Actor.ID != "admin_1" || entry.Actor.Role != "superadmin" {
		t.Errorf("actor info not captured: %+v", entry.Actor)
	}
	if entry.Outcome.Status != OutcomeSuccess || entry.Outcome.StatusCode != http.StatusCreated {
		t.Errorf("outcome incorrect: %+v", entry.Outcome)
	}

	// 2. GET request should NOT be logged by DefaultAuditPolicy when successful
	reqGet := httptest.NewRequest(http.MethodGet, "/api/users", nil)
	recGet := httptest.NewRecorder()
	e.ServeHTTP(recGet, reqGet)

	if memSink.Len() != 1 {
		t.Errorf("expected GET request to be skipped by DefaultAuditPolicy, but total is %d", memSink.Len())
	}
}

func TestAuditMiddleware_Skipper_HealthProbes(t *testing.T) {
	cfg := DefaultAuditConfig()
	e, memSink := setupTestEcho(cfg)

	e.GET("/healthz", func(c *echo.Context) error {
		return c.String(http.StatusOK, "healthy")
	})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if memSink.Len() != 0 {
		t.Errorf("expected health probe to be completely skipped by DefaultAuditSkipper")
	}
}

func TestAuditMiddleware_HandlerEnrichment(t *testing.T) {
	cfg := DefaultAuditConfig()
	e, memSink := setupTestEcho(cfg)

	e.PUT("/api/orders/:id", func(c *echo.Context) error {
		orderID := c.Param("id")

		// Enrich audit entry in business logic
		entry := FromContext(c)
		if entry != nil {
			entry.WithTarget("order", orderID, "Customer Order").
				WithCategory(CategoryData).
				WithDiff(
					map[string]any{"status": "processing"},
					map[string]any{"status": "shipped"},
				)
		}
		return c.String(http.StatusOK, "order updated")
	})

	req := httptest.NewRequest(http.MethodPut, "/api/orders/ord_999", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if memSink.Len() != 1 {
		t.Fatalf("expected 1 audit entry, got %d", memSink.Len())
	}

	entry := memSink.Last()
	if entry.Target.Type != "order" || entry.Target.ID != "ord_999" {
		t.Errorf("target not enriched by handler: %+v", entry.Target)
	}
	if len(entry.Changes.Diff) != 1 || entry.Changes.Diff[0].Field != "status" {
		t.Errorf("diff not enriched by handler: %+v", entry.Changes)
	}
}

func TestAuditMiddleware_RequestBodySanitization(t *testing.T) {
	cfg := DefaultAuditConfig()
	cfg.IncludeRequestBody = true
	e, memSink := setupTestEcho(cfg)

	e.POST("/api/auth/register", func(c *echo.Context) error {
		return c.String(http.StatusOK, "registered")
	})

	payload := `{"username":"carol","password":"superSecretPassword123","email":"carol@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/auth/register", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if memSink.Len() != 1 {
		t.Fatalf("expected 1 audit entry, got %d", memSink.Len())
	}

	entry := memSink.Last()
	reqBody, ok := entry.Metadata["request_body"].(map[string]any)
	if !ok {
		t.Fatalf("request_body missing from metadata: %+v", entry.Metadata)
	}

	if reqBody["password"] != privacy.RedactedString {
		t.Errorf("sensitive password was NOT redacted in audit body metadata: %v", reqBody["password"])
	}
	if reqBody["username"] != "carol" {
		t.Errorf("username was improperly modified: %v", reqBody["username"])
	}
}

func TestAuditMiddleware_ErrorAndDeniedStatus(t *testing.T) {
	cfg := DefaultAuditConfig()
	e, memSink := setupTestEcho(cfg)

	e.GET("/api/secret", func(c *echo.Context) error {
		return echo.NewHTTPError(http.StatusForbidden, "Access Denied: Missing permissions")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/secret", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if memSink.Len() != 1 {
		t.Fatalf("expected 403 GET request to be logged by DefaultAuditPolicy, got %d", memSink.Len())
	}

	entry := memSink.Last()
	if entry.Outcome.Status != OutcomeDenied {
		t.Errorf("expected OutcomeDenied for 403, got %s", entry.Outcome.Status)
	}
	if entry.Outcome.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403, got %d", entry.Outcome.StatusCode)
	}
	if !strings.Contains(entry.Outcome.Reason, "Access Denied") {
		t.Errorf("expected error reason to be recorded, got %s", entry.Outcome.Reason)
	}
}
