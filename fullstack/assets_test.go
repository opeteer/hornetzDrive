package fullstack

import (
	"net/http"
	"net/http/httptest"
	"os"
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

	// Test global AssetURL helper
	if AssetURL("css/app.css") != "/assets/css/app.hash123.css" {
		t.Errorf("expected global AssetURL helper to resolve properly")
	}

	e := echo.New()
	am.Mount(e)

	req := httptest.NewRequest(http.MethodGet, "/assets/css/app.hash123.css", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Header().Get("Cache-Control") != "public, max-age=31536000, immutable" {
		t.Errorf("Expected prod immutable cache headers, got %s", rec.Header().Get("Cache-Control"))
	}
}
