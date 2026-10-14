package download

import "testing"

func TestSniffMagicBytes(t *testing.T) {
	tests := []struct {
		name             string
		buf              []byte
		proposedName     string
		proposedMime     string
		expectedFilename string
		expectedMime     string
	}{
		{
			name:             "PDF file with generic name",
			buf:              []byte("%PDF-1.7 standard pdf document header"),
			proposedName:     "download",
			proposedMime:     "application/octet-stream",
			expectedFilename: "download.pdf",
			expectedMime:     "application/pdf",
		},
		{
			name:             "ZIP file with .bin extension",
			buf:              []byte{0x50, 0x4b, 0x03, 0x04, 0x14, 0x00},
			proposedName:     "archive.bin",
			proposedMime:     "application/octet-stream",
			expectedFilename: "archive.zip",
			expectedMime:     "application/zip",
		},
		{
			name:             "GZIP file with .dat extension",
			buf:              []byte{0x1f, 0x8b, 0x08, 0x00},
			proposedName:     "payload.dat",
			proposedMime:     "application/octet-stream",
			expectedFilename: "payload.gz",
			expectedMime:     "application/gzip",
		},
		{
			name:             "PNG image with .tmp extension",
			buf:              []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00},
			proposedName:     "screenshot.tmp",
			proposedMime:     "application/octet-stream",
			expectedFilename: "screenshot.png",
			expectedMime:     "image/png",
		},
		{
			name:             "JPEG image without extension",
			buf:              []byte{0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10},
			proposedName:     "photo",
			proposedMime:     "",
			expectedFilename: "photo.jpg",
			expectedMime:     "image/jpeg",
		},
		{
			name:             "SQLite database without extension",
			buf:              []byte("SQLite format 3\x00\x10\x00\x01\x01"),
			proposedName:     "database",
			proposedMime:     "application/octet-stream",
			expectedFilename: "database.sqlite",
			expectedMime:     "application/vnd.sqlite3",
		},
		{
			name:             "Already has correct extension - preserved",
			buf:              []byte("%PDF-1.4 header"),
			proposedName:     "financial_statement.pdf",
			proposedMime:     "application/pdf",
			expectedFilename: "financial_statement.pdf",
			expectedMime:     "application/pdf",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotName, gotMime := SniffMagicBytes(tc.buf, tc.proposedName, tc.proposedMime)
			if gotName != tc.expectedFilename {
				t.Errorf("SniffMagicBytes filename = %q; expected %q", gotName, tc.expectedFilename)
			}
			if gotMime != tc.expectedMime {
				t.Errorf("SniffMagicBytes mime = %q; expected %q", gotMime, tc.expectedMime)
			}
		})
	}
}

func TestIsHTMLPayload(t *testing.T) {
	htmlSamples := [][]byte{
		[]byte("<!DOCTYPE html><html><head><title>Test</title></head><body></body></html>"),
		[]byte("  <!doctype html>\n<html>"),
		[]byte("<html><head></head><body>Error page</body></html>"),
		[]byte("<?xml version=\"1.0\"?><html xmlns=\"http://www.w3.org/1999/xhtml\">"),
		[]byte("<head><meta http-equiv=\"refresh\" content=\"0\"></head>"),
		[]byte("<script>window.location.href='https://example.com';</script>"),
	}

	for i, sample := range htmlSamples {
		if !IsHTMLPayload(sample) {
			t.Errorf("Sample #%d expected IsHTMLPayload = true, got false (%q)", i, string(sample[:20]))
		}
	}

	binarySamples := [][]byte{
		{0x50, 0x4b, 0x03, 0x04}, // PK zip
		{0x1f, 0x8b, 0x08, 0x00}, // gzip
		[]byte("%PDF-1.7"),
		{0x89, 0x50, 0x4e, 0x47}, // PNG
		[]byte("Plain text content without html tags"),
	}

	for i, sample := range binarySamples {
		if IsHTMLPayload(sample) {
			t.Errorf("Binary sample #%d expected IsHTMLPayload = false, got true", i)
		}
	}
}

func TestIsBinaryExtension(t *testing.T) {
	binaryFiles := []string{
		"game.zip", "data.rar", "archive.7z", "source.tar.gz", "setup.exe",
		"disk.iso", "payload.bin", "report.pdf", "clip.mp4", "image.png",
	}
	for _, f := range binaryFiles {
		if !IsBinaryExtension(f) {
			t.Errorf("Expected IsBinaryExtension(%q) = true", f)
		}
	}

	nonBinaryFiles := []string{
		"index.html", "about.htm", "styles.css", "script.js", "notes.txt", "data.json",
	}
	for _, f := range nonBinaryFiles {
		if IsBinaryExtension(f) {
			t.Errorf("Expected IsBinaryExtension(%q) = false", f)
		}
	}
}
