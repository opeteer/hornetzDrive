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

func TestLayout_LucideIcons(t *testing.T) {
	comp := Layout("Test Page")
	var buf bytes.Buffer
	err := comp.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Failed to render Layout: %v", err)
	}

	html := buf.String()

	// Verify SVG icons with Lucide standard viewBox and attributes are present
	if !strings.Contains(html, "viewBox=\"0 0 24 24\"") {
		t.Errorf("Layout HTML does not contain Lucide SVG icons with viewBox=\"0 0 24 24\"")
	}

	// Verify getFileIconSvg helper is available in Alpine store
	if !strings.Contains(html, "getFileIconSvg(icon, extraClass") {
		t.Errorf("Layout HTML does not define getFileIconSvg helper in Alpine store")
	}

	// Verify emojis are not present in layout
	emojis := []string{"📁", "🛡️", "🗑️", "⭐", "🕒", "🐝", "⚡", "🔒", "🚨"}
	for _, em := range emojis {
		if strings.Contains(html, em) {
			t.Errorf("Layout HTML still contains legacy emoji %q", em)
		}
	}
}

func TestDashboard_LucideIcons(t *testing.T) {
	comp := DashboardContent()
	var buf bytes.Buffer
	err := comp.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Failed to render DashboardContent: %v", err)
	}

	html := buf.String()

	// Verify Lucide SVGs are rendered
	if !strings.Contains(html, "viewBox=\"0 0 24 24\"") {
		t.Errorf("Dashboard HTML does not contain Lucide SVG icons with viewBox=\"0 0 24 24\"")
	}

	// Verify file dynamic icon utilizes getFileIconSvg
	if !strings.Contains(html, "$store.drive.getFileIconSvg") {
		t.Errorf("Dashboard HTML does not use $store.drive.getFileIconSvg for dynamic file icons")
	}

	// Verify emojis are not present in dashboard
	emojis := []string{"🗑️", "🔒", "田", "≡", "📁", "🛡️", "✏️", "⭐", "🕒", "📭", "📄", "♻️", "📥", "★", "☆"}
	for _, em := range emojis {
		if strings.Contains(html, em) {
			t.Errorf("Dashboard HTML still contains legacy emoji %q", em)
		}
	}
}
