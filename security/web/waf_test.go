package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestWAF_SQLi_Blocked(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?id=1%20UNION%20SELECT%20username,password%20FROM%20users", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected HTTP 403 Forbidden for SQLi attempt, got %d", rec.Code)
	}
}

func TestWAF_XSS_Blocked(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected HTTP 403 Forbidden for XSS attempt, got %d", rec.Code)
	}
}

func TestWAF_JSON_PostBody_Allowed(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.POST("/test", func(c *echo.Context) error {
		var payload struct {
			Name string `json:"name"`
		}
		if err := c.Bind(&payload); err != nil {
			return err
		}
		return c.String(http.StatusOK, "hello "+payload.Name)
	})

	jsonBody := []byte(`{"name": "Alice"}`)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 OK for valid JSON POST body, got %d", rec.Code)
	}
	if rec.Body.String() != "hello Alice" {
		t.Errorf("expected body to yield 'hello Alice', got %q", rec.Body.String())
	}
}

func TestWAF_ValidRequest_Allowed(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?name=john_doe&page=2", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 OK for valid request, got %d", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// Objective Framework Weakness & Vulnerability Exposure Tests
// -----------------------------------------------------------------------------

// TestWAF_Weakness_MultilineXSS demonstrates that WAF fails to block multiline script tags
// because regexp dot (.) in xssPatterns does not match newline characters by default.
func TestWAF_Weakness_MultilineXSS(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "executed")
	})

	// Multiline payload with newlines %0A
	req := httptest.NewRequest(http.MethodGet, "/test?q=%3Cscript%3E%0Aalert(1)%0A%3C/script%3E", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// Patched: WAF should now block this with HTTP 403
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for multiline XSS payload, got %d", rec.Code)
	}
}

// TestWAF_Weakness_EventHandlerXSS demonstrates that WAF misses HTML event handler injection vectors.
func TestWAF_Weakness_EventHandlerXSS(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "executed")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?q=%3Cimg%20src=x%20onerror=alert(1)%3E", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for HTML event handler XSS payload, got %d", rec.Code)
	}
}

// TestWAF_Weakness_DoubleURLEncoding demonstrates double URL encoding bypass.
func TestWAF_Weakness_DoubleURLEncoding(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "executed")
	})

	// %253C -> %3C script %253E -> %3E
	req := httptest.NewRequest(http.MethodGet, "/test?q=%253Cscript%253Ealert(1)%253C/script%253E", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for double URL encoded XSS payload, got %d", rec.Code)
	}
}

// TestWAF_Weakness_PostBodyIgnored demonstrates that WAF completely ignores POST payload body inspection.
func TestWAF_Weakness_PostBodyIgnored(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.POST("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "processed")
	})

	sqliJSON := []byte(`{"query": "UNION SELECT username, password FROM users"}`)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer(sqliJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for POST body SQLi payload, got %d", rec.Code)
	}
}

// TestWAF_Weakness_SQLCommentBypass demonstrates SQL comment bypass of `union\s+select`.
func TestWAF_Weakness_SQLCommentBypass(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "executed")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?id=1%20UNION/*foo*/SELECT%20password%20FROM%20users", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 for SQL comment obfuscated payload, got %d", rec.Code)
	}
}
