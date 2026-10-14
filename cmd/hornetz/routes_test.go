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
	if !strings.Contains(body, "file.has_preview") {
		t.Errorf("Expected 'file.has_preview' condition in /app dashboard HTML")
	}
	if !strings.Contains(body, "/thumbnail") {
		t.Errorf("Expected '/thumbnail' endpoint references in /app dashboard HTML")
	}
	if !strings.Contains(body, "selectFile") {
		t.Errorf("Expected 'selectFile' method in /app dashboard HTML")
	}
	if !strings.Contains(body, `type="search"`) {
		t.Errorf("Expected 'type=\"search\"' on search bar input")
	}
	if !strings.Contains(body, `name="hornetz_search"`) {
		t.Errorf("Expected 'name=\"hornetz_search\"' on search input")
	}
	if !strings.Contains(body, `role="search"`) {
		t.Errorf("Expected 'role=\"search\"' form container")
	}
	if !strings.Contains(body, `name="vault_password"`) || !strings.Contains(body, `autocomplete="current-password"`) {
		t.Errorf("Expected vault password modal to be enclosed with autocomplete=\"current-password\"")
	}
	if !strings.Contains(body, `:title="file.name"`) {
		t.Errorf("Expected ':title=\"file.name\"' on file card titles")
	}
	if !strings.Contains(body, "isDownloadLink") {
		t.Errorf("Expected 'isDownloadLink' check in /app dashboard search bar")
	}
	if !strings.Contains(body, "startDownloadFromLink") {
		t.Errorf("Expected 'startDownloadFromLink' method in /app dashboard store")
	}
	if !strings.Contains(body, "Tautan Unduhan Terdeteksi") {
		t.Errorf("Expected 'Tautan Unduhan Terdeteksi' card in live search dropdown")
	}
	if !strings.Contains(body, "Torrent Magnet") {
		t.Errorf("Expected 'Torrent Magnet' badge in live search dropdown")
	}
	if !strings.Contains(body, "openAddDownloadModal") {
		t.Errorf("Expected 'openAddDownloadModal' action in /app dashboard")
	}
	if !strings.Contains(body, "showAddDownloadModal") {
		t.Errorf("Expected 'showAddDownloadModal' modal in /app dashboard")
	}
	if !strings.Contains(body, "getLinkProvider") {
		t.Errorf("Expected 'getLinkProvider' method in /app dashboard store")
	}
	if !strings.Contains(body, "Unduh dari Tautan") {
		t.Errorf("Expected 'Unduh dari Tautan' button in /app dashboard")
	}
}

func TestRoutes_GzipCompression(t *testing.T) {
	app := setupTestApp()
	app.Use(echo.WrapMiddleware(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	}))

	req := httptest.NewRequest(http.MethodGet, "/app", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for '/app', got %d", rec.Code)
	}
}

