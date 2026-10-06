package components

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestLandingPage_Render(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	comp := LandingPage(c)
	var buf bytes.Buffer
	err := comp.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Failed to render LandingPage: %v", err)
	}

	html := buf.String()

	// Verify key brand and landing elements
	expectedPhrases := []string{
		"Hornetz",
		"Drive",
		"Zero-Trust",
		"AES-256-GCM",
		"Content-Addressable Storage",
		"Chitin Shuffler",
		"Stinger Panic Purge",
		"href=\"/app\"",
		"id=\"demo\"",
		"id=\"fitur\"",
		"id=\"kalkulator\"",
		"id=\"arsitektur\"",
		"id=\"spesifikasi\"",
		"id=\"faq\"",
		"landingApp()",
		"/api/storage/stats",
	}

	for _, phrase := range expectedPhrases {
		if !strings.Contains(html, phrase) {
			t.Errorf("Landing page missing expected content: %q", phrase)
		}
	}
}
