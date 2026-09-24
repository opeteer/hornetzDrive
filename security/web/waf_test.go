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

func TestWAF_Traversal_Blocked(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.GET("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	req := httptest.NewRequest(http.MethodGet, "/test?path=../../etc/passwd", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected HTTP 403 Forbidden for Path Traversal attempt, got %d", rec.Code)
	}
}

func TestWAF_JSON_PostBody_Blocked(t *testing.T) {
	e := echo.New()
	e.Use(WAF())
	e.POST("/test", func(c *echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	jsonBody := []byte(`{"query": "UNION SELECT username FROM users"}`)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected HTTP 403 Forbidden for JSON POST SQLi attempt, got %d", rec.Code)
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
		t.Errorf("expected body re-buffering to work and yield 'hello Alice', got %q", rec.Body.String())
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
