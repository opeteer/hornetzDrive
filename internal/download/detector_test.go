package download

import "testing"

func TestIsDownloadLink(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"http://example.com/file.zip", true},
		{"https://storage.googleapis.com/test.iso", true},
		{"magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709", true},
		{"magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=sample.iso", true},
		{"  https://example.com/file.pdf  ", true},
		{"", false},
		{"normal search text", false},
		{"http", false},
		{"https://", false},
		{"magnet:?", false},
		{"file.pdf", false},
		{"ftp://example.com/file.bin", false},
	}

	for _, tt := range tests {
		got := IsDownloadLink(tt.input)
		if got != tt.expected {
			t.Errorf("IsDownloadLink(%q) = %v; expected %v", tt.input, got, tt.expected)
		}
	}
}

func TestCleanFilename(t *testing.T) {
	tests := []struct {
		name     string
		fallback string
		expected string
	}{
		{"normal.txt", "fallback.txt", "normal.txt"},
		{"../../../etc/passwd", "fallback.txt", "passwd"},
		{"file\"with*quotes?.dat", "fallback.txt", "file_with*quotes?.dat"},
		{"", "fallback.txt", "fallback.txt"},
		{".", "fallback.txt", "fallback.txt"},
		{"..", "fallback.txt", "fallback.txt"},
		{"...", "fallback.txt", "fallback.txt"},
		{".  ", "fallback.txt", "fallback.txt"},
		{"___", "fallback.txt", "fallback.txt"},
		{"/", "fallback.txt", "fallback.txt"},
		{".env", "fallback.txt", ".env"},
		{".gitignore", "fallback.txt", ".gitignore"},
		{".bashrc", "fallback.txt", ".bashrc"},
		{".dockerignore", "fallback.txt", ".dockerignore"},
		{"__init__.py", "fallback.txt", "__init__.py"},
		{"_header.scss", "fallback.txt", "_header.scss"},
		{"my document.pdf  ", "fallback.txt", "my document.pdf"},
		{"subdir/.env", "fallback.txt", ".env"},
	}

	for _, tt := range tests {
		got := CleanFilename(tt.name, tt.fallback)
		if got != tt.expected {
			t.Errorf("CleanFilename(%q, %q) = %q; expected %q", tt.name, tt.fallback, got, tt.expected)
		}
	}
}
