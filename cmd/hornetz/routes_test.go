package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/internal/ui/components"
)

func setupTestApp() *echo.Echo {
	e := echo.New()
	e.GET("/", func(c *echo.Context) error {
		return components.LandingPage(c).Render(c.Request().Context(), c.Response())
	})
	e.GET("/app", func(c *echo.Context) error {
		return components.Dashboard(c).Render(c.Request().Context(), c.Response())
	})
	e.GET("/drive", func(c *echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/app")
	})
	e.GET("/dashboard", func(c *echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/app")
	})
	return e
}

func TestRoutes_LandingPage(t *testing.T) {
	app := setupTestApp()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for '/', got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Hornetz Drive") {
		t.Errorf("Expected 'Hornetz Drive' on landing page")
	}
	if !strings.Contains(body, "Benteng Awan Terenkripsi") {
		t.Errorf("Expected 'Benteng Awan Terenkripsi' heading on landing page")
	}
}

func TestRoutes_Redirects(t *testing.T) {
	app := setupTestApp()

	// Test /drive redirect
	req1 := httptest.NewRequest(http.MethodGet, "/drive", nil)
	rec1 := httptest.NewRecorder()
	app.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusMovedPermanently {
		t.Errorf("Expected 301 for '/drive', got %d", rec1.Code)
	}
	if loc := rec1.Header().Get("Location"); loc != "/app" {
		t.Errorf("Expected Location '/app', got %s", loc)
	}

	// Test /dashboard redirect
	req2 := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rec2 := httptest.NewRecorder()
	app.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusMovedPermanently {
		t.Errorf("Expected 301 for '/dashboard', got %d", rec2.Code)
	}
	if loc := rec2.Header().Get("Location"); loc != "/app" {
		t.Errorf("Expected Location '/app', got %s", loc)
	}
}

func TestRoutes_DashboardApp(t *testing.T) {
	app := setupTestApp()

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for '/app', got %d", rec.Code)
	}

	body := rec.Body.String()
	if !strings.Contains(body, "Dashboard Storage") {
		t.Errorf("Expected 'Dashboard Storage' title in /app dashboard")
	}
	if !strings.Contains(body, "Beranda") {
		t.Errorf("Expected 'Beranda' home link in /app dashboard header")
	}
}

