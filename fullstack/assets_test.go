package fullstack

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestAssetManager_DevMode(t *testing.T) {
	tempDir := t.TempDir()
	fsys := os.DirFS(tempDir)

	am, err := NewAssetManager(fsys, true, "/static")
	if err != nil {
		t.Fatalf("NewAssetManager failed: %v", err)
	}

	url := am.GetURL("app.js")
	// Should look like /static/app.js?v=169...
	if url[:14] != "/static/app.js" {
		t.Errorf("expected /static/app.js prefix, got %s", url)
	}

	e := echo.New()
	am.Mount(e)

	// Create dummy file
	os.WriteFile(tempDir+"/app.js", []byte("ok"), 0644)

	req := httptest.NewRequest(http.MethodGet, "/static/app.js", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK, got %d", rec.Code)
	}
	if rec.Header().Get("Cache-Control") != "no-cache, no-store, must-revalidate" {
		t.Errorf("Expected dev cache headers, got %s", rec.Header().Get("Cache-Control"))
	}
}

func TestAssetManager_ProdMode(t *testing.T) {
	tempDir := t.TempDir()
	
	// Pre-generate manifest
	manifestContent := `{"css/app.css": "css/app.hash123.css"}`
	os.Mkdir(tempDir+"/css", 0755)
	os.WriteFile(tempDir+"/css/app.hash123.css", []byte("css"), 0644)
	os.WriteFile(tempDir+"/manifest.json", []byte(manifestContent), 0644)

	fsys := os.DirFS(tempDir)

	am, err := NewAssetManager(fsys, false, "/assets")
	if err != nil {
		t.Fatalf("NewAssetManager failed: %v", err)
	}

	url := am.GetURL("css/app.css")
	if url != "/assets/css/app.hash123.css" {
		t.Errorf("expected resolved hash URL, got %s", url)
	}

	// Test leading slash
	urlSlashed := am.GetURL("/css/app.css")
	if urlSlashed != "/assets/css/app.hash123.css" {
		t.Errorf("expected resolved hash URL without double slashes, got %s", urlSlashed)
	}

	// Test basename matching (e.g. /assets/css/app.css -> app.css or css/app.css)
	urlPrefixed := am.GetURL("/assets/css/app.css")
	if urlPrefixed != "/assets/css/app.hash123.css" {
		t.Errorf("expected basename/prefixed path to resolve, got %s", urlPrefixed)
	}

	// Test global AssetURL helper
	if AssetURL("css/app.css") != "/assets/css/app.hash123.css" {
		t.Errorf("expected global AssetURL helper to resolve properly")
	}
	if AssetURL("/assets/css/app.css") != "/assets/css/app.hash123.css" {
		t.Errorf("expected global AssetURL helper with prefixed path to resolve properly")
	}

	// Test flat manifest without directory: "bundle.css" -> "bundle.flat999.css"
	amFlat, err := NewAssetManager(fsys, false, "/static")
	if err != nil {
		t.Fatalf("NewAssetManager failed: %v", err)
	}
	amFlat.manifest = Manifest{"bundle.css": "bundle.flat999.css"}
	if got := amFlat.GetURL("/assets/css/bundle.css"); got != "/static/bundle.flat999.css" {
		t.Errorf("expected basename match for flat manifest, got %s", got)
	}

	e := echo.New()
	am.Mount(e)

	// 1. Hashed asset in manifest should receive immutable 1-year cache headers
	req := httptest.NewRequest(http.MethodGet, "/assets/css/app.hash123.css", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("Expected prod immutable cache headers for hashed asset, got %s", rec.Header().Get("Cache-Control"))
	}

	// 2. Unversioned asset NOT in manifest must receive revalidating cache headers (BUG-UX-22)
	os.WriteFile(tempDir+"/css/plain.css", []byte("plain"), 0644)
	reqPlain := httptest.NewRequest(http.MethodGet, "/assets/css/plain.css", nil)
	recPlain := httptest.NewRecorder()
	e.ServeHTTP(recPlain, reqPlain)

	if recPlain.Header().Get("Cache-Control") != "public, max-age=3600, must-revalidate" {
		t.Errorf("Expected must-revalidate cache header for unversioned asset, got %s", recPlain.Header().Get("Cache-Control"))
	}

	// 3. Asset with ?v= version query parameter should receive immutable caching
	reqVersioned := httptest.NewRequest(http.MethodGet, "/assets/css/plain.css?v=12345", nil)
	recVersioned := httptest.NewRecorder()
	e.ServeHTTP(recVersioned, reqVersioned)

	if recVersioned.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("Expected immutable cache headers for version-queried asset, got %s", recVersioned.Header().Get("Cache-Control"))
	}

	// 4. Fallback GetURL for unmanifested asset should automatically append ?v=
	unmanifestedURL := am.GetURL("css/plain.css")
	if unmanifestedURL[:20] != "/assets/css/plain.cs" || !strings.Contains(unmanifestedURL, "?v=") {
		t.Errorf("Expected GetURL to append ?v= cache-buster for unmanifested asset, got %s", unmanifestedURL)
	}
}
