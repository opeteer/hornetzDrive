package components

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestLayout_PlusJakartaSansFont(t *testing.T) {
	comp := Layout("Test Page")
	var buf bytes.Buffer
	err := comp.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Failed to render Layout: %v", err)
	}

	html := buf.String()

	// Verify Plus Jakarta Sans font stylesheet inclusion
	if !strings.Contains(html, "family=Plus+Jakarta+Sans") {
		t.Errorf("Layout HTML does not include Google Fonts stylesheet for Plus Jakarta Sans")
	}

	// Verify Tailwind font-family configuration for Plus Jakarta Sans
	if !strings.Contains(html, "sans: ['\"Plus Jakarta Sans\"', 'sans-serif']") {
		t.Errorf("Layout HTML does not configure Tailwind with Plus Jakarta Sans font family")
	}

	// Verify body and font-sans CSS font-family rule
	if !strings.Contains(html, "font-family: 'Plus Jakarta Sans', sans-serif") {
		t.Errorf("Layout HTML does not apply font-family: 'Plus Jakarta Sans', sans-serif")
	}
}

func TestLandingPage_PlusJakartaSansFont(t *testing.T) {
	comp := LandingPage(nil)
	var buf bytes.Buffer
	err := comp.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Failed to render LandingPage: %v", err)
	}

	html := buf.String()

	// Verify Plus Jakarta Sans font stylesheet inclusion
	if !strings.Contains(html, "family=Plus+Jakarta+Sans") {
		t.Errorf("LandingPage HTML does not include Google Fonts stylesheet for Plus Jakarta Sans")
	}

	// Verify Tailwind font-family configuration for Plus Jakarta Sans
	if !strings.Contains(html, "sans: ['\"Plus Jakarta Sans\"', 'sans-serif']") {
		t.Errorf("LandingPage HTML does not configure Tailwind with Plus Jakarta Sans font family")
	}

	// Verify body and font-sans CSS font-family rule
	if !strings.Contains(html, "font-family: 'Plus Jakarta Sans', sans-serif") {
		t.Errorf("LandingPage HTML does not apply font-family: 'Plus Jakarta Sans', sans-serif")
	}
}
