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

func TestDashboard_SortDropdownZIndex(t *testing.T) {
	comp := DashboardContent()
	var buf bytes.Buffer
	err := comp.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Failed to render DashboardContent: %v", err)
	}

	html := buf.String()

	// Verify action bar has higher z-index (z-20) to stay above workspace content (z-10)
	if !strings.Contains(html, "hornetz-glass shrink-0 relative z-20") {
		t.Errorf("Dashboard Action Bar does not have relative z-20")
	}

	// Verify sort dropdown menu has z-50 to float above any elements
	if !strings.Contains(html, "z-50") {
		t.Errorf("Dashboard sort dropdown does not have z-50")
	}
}

func TestLayout_HeaderSearchReplacesLogo(t *testing.T) {
	comp := Layout("Test Page")
	var buf bytes.Buffer
	err := comp.Render(context.Background(), &buf)
	if err != nil {
		t.Fatalf("Failed to render Layout: %v", err)
	}

	html := buf.String()

	// Verify the HornetzDrive logo and subtitle have been removed from the application header
	if strings.Contains(html, "v2.0 Cloud") {
		t.Errorf("Layout header still contains 'v2.0 Cloud' logo badge")
	}
	if strings.Contains(html, "Penyimpanan Awan Terenkripsi Real-Time") {
		t.Errorf("Layout header still contains 'Penyimpanan Awan Terenkripsi Real-Time' subtitle")
	}

	// Verify the search bar is present in the header
	if !strings.Contains(html, `name="hornetz_search"`) {
		t.Errorf("Layout header does not contain search input")
	}
	if !strings.Contains(html, `id="hornetz-search-input"`) {
		t.Errorf("Layout header does not contain search input id")
	}

	// Verify right-side controls are present
	if !strings.Contains(html, "Pengguna Utama") {
		t.Errorf("Layout header missing user profile")
	}
	if !strings.Contains(html, "Beranda") {
		t.Errorf("Layout header missing Beranda navigation link")
	}
}


