package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/internal/ui/components"
	"ztatic-go-framework/security/web"
)

func setupTestApp() *echo.Echo {
	e := echo.New()

	subFS, err := fs.Sub(ztatic.AssetsFS, "assets")
	if err == nil {
		if assetMgr, err := fullstack.NewAssetManager(subFS, false, "/assets"); err == nil {
			assetMgr.Mount(e)
		}
	}

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
	if !strings.Contains(body, "downloadFolder") {
		t.Errorf("Expected 'downloadFolder' method in /app dashboard store")
	}
	if !strings.Contains(body, "downloadCurrentFolder") {
		t.Errorf("Expected 'downloadCurrentFolder' method in /app dashboard store")
	}
	if !strings.Contains(body, "Unduh Folder (ZIP)") {
		t.Errorf("Expected 'Unduh Folder (ZIP)' button in /app dashboard")
	}
	if !strings.Contains(body, "Unduh ZIP") {
		t.Errorf("Expected 'Unduh ZIP' action in folder dropdown menu")
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

func TestRoutes_SecurityHeaders_CSP(t *testing.T) {
	cfg := ztatic.DefaultConfig()
	cfg.Security.Headers.EnableCSPNonce = false
	cfg.Security.Headers.ContentSecurityPolicy = "default-src 'self'; frame-src 'self' blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://cdn.tailwindcss.com https://cdn.skypack.dev https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' blob:; worker-src 'self' blob:; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';"

	e := echo.New()
	e.Use(web.SecureHeadersWithConfig(cfg.Security.Headers))
	e.GET("/api/files/test/preview", func(c *echo.Context) error {
		return c.String(http.StatusOK, "pdf-content")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/files/test/preview", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Errorf("Expected CSP to contain \"frame-ancestors 'self'\", got %q", csp)
	}
	if strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("CSP should not contain \"frame-ancestors 'none'\", got %q", csp)
	}
	if !strings.Contains(csp, "frame-src 'self'") {
		t.Errorf("Expected CSP to contain \"frame-src 'self'\", got %q", csp)
	}
}

func TestStaticAssets_DeliveryAndIntegrity(t *testing.T) {
	app := setupTestApp()

	// 1. Verify CSS delivery
	cssURL := fullstack.AssetURL("css/main.css")
	if !strings.HasPrefix(cssURL, "/assets/css/main.css") {
		t.Errorf("Expected AssetURL('css/main.css') to start with /assets/css/main.css, got %q", cssURL)
	}

	reqCSS := httptest.NewRequest(http.MethodGet, cssURL, nil)
	recCSS := httptest.NewRecorder()
	app.ServeHTTP(recCSS, reqCSS)

	if recCSS.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 for main.css, got %d. Body: %s", recCSS.Code, recCSS.Body.String())
	}
	if ct := recCSS.Header().Get("Content-Type"); !strings.Contains(ct, "text/css") {
		t.Errorf("Expected Content-Type text/css for main.css, got %q", ct)
	}
	cssBody := recCSS.Body.String()
	if !strings.Contains(cssBody, ".hidden") {
		t.Errorf("Expected main.css to define .hidden class, but it was missing")
	}

	// 2. Verify Alpine.js delivery
	alpineURL := fullstack.AssetURL("js/alpine.min.js")
	reqAlpine := httptest.NewRequest(http.MethodGet, alpineURL, nil)
	recAlpine := httptest.NewRecorder()
	app.ServeHTTP(recAlpine, reqAlpine)

	if recAlpine.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 for alpine.min.js, got %d. Body: %s", recAlpine.Code, recAlpine.Body.String())
	}
	if len(recAlpine.Body.Bytes()) < 1000 {
		t.Errorf("Expected valid alpine.min.js content, got length %d", len(recAlpine.Body.Bytes()))
	}

	// 3. Verify other vendored JS delivery
	for _, jsAsset := range []string{"js/turbo_downloader.js", "js/reconcile_tree.js"} {
		url := fullstack.AssetURL(jsAsset)
		req := httptest.NewRequest(http.MethodGet, url, nil)
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("Expected HTTP 200 for %s, got %d", jsAsset, rec.Code)
		}
	}
}

func TestStaticAssets_DefensiveAutoSub(t *testing.T) {
	e := echo.New()
	// Pass raw ztatic.AssetsFS without fs.Sub; NewAssetManager should auto-sub into "assets"
	assetMgr, err := fullstack.NewAssetManager(ztatic.AssetsFS, false, "/assets")
	if err != nil {
		t.Fatalf("NewAssetManager failed: %v", err)
	}
	assetMgr.Mount(e)

	cssURL := fullstack.AssetURL("css/main.css")
	req := httptest.NewRequest(http.MethodGet, cssURL, nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Defensive auto-sub failed: expected 200 for main.css, got %d", rec.Code)
	}
}

