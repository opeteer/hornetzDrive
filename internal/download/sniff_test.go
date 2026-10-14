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
