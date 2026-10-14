package download

import (
	"bytes"
	"net/http"
	"path/filepath"
	"strings"
)

type magicSignature struct {
	offset int
	sig    []byte
	ext    string
	mime   string
}

var magicSignatures = []magicSignature{
	{offset: 0, sig: []byte{0x25, 0x50, 0x44, 0x46, 0x2d}, ext: ".pdf", mime: "application/pdf"},                      // %PDF-
	{offset: 0, sig: []byte{0x50, 0x4b, 0x03, 0x04}, ext: ".zip", mime: "application/zip"},                              // PK.. (ZIP / Office)
	{offset: 0, sig: []byte{0x1f, 0x8b}, ext: ".gz", mime: "application/gzip"},                                          // GZIP
	{offset: 0, sig: []byte{0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c}, ext: ".7z", mime: "application/x-7z-compressed"},      // 7z
	{offset: 0, sig: []byte{0x52, 0x61, 0x72, 0x21, 0x1a, 0x07}, ext: ".rar", mime: "application/vnd.rar"},             // RAR
	{offset: 0, sig: []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}, ext: ".png", mime: "image/png"},          // PNG
	{offset: 0, sig: []byte{0xff, 0xd8, 0xff}, ext: ".jpg", mime: "image/jpeg"},                                         // JPEG
	{offset: 0, sig: []byte("GIF87a"), ext: ".gif", mime: "image/gif"},                                                  // GIF87a
	{offset: 0, sig: []byte("GIF89a"), ext: ".gif", mime: "image/gif"},                                                  // GIF89a
	{offset: 0, sig: []byte("SQLite format 3\x00"), ext: ".sqlite", mime: "application/vnd.sqlite3"},                    // SQLite
	{offset: 0, sig: []byte("fLaC"), ext: ".flac", mime: "audio/flac"},                                                   // FLAC
	{offset: 0, sig: []byte("OggS"), ext: ".ogg", mime: "audio/ogg"},                                                     // OGG
	{offset: 0, sig: []byte("ID3"), ext: ".mp3", mime: "audio/mpeg"},                                                     // MP3 ID3
	{offset: 4, sig: []byte("ftyp"), ext: ".mp4", mime: "video/mp4"},                                                     // MP4 ftyp
	{offset: 0, sig: []byte{0x1a, 0x45, 0xdf, 0xa3}, ext: ".mkv", mime: "video/x-matroska"},                            // Matroska / WebM
	{offset: 0, sig: []byte{0x7f, 0x45, 0x4c, 0x46}, ext: ".elf", mime: "application/x-executable"},                    // ELF binary
	{offset: 0, sig: []byte{0x4d, 0x5a}, ext: ".exe", mime: "application/x-msdownload"},                                 // DOS / Windows PE MZ
	{offset: 0, sig: []byte{0x00, 0x61, 0x73, 0x6d}, ext: ".wasm", mime: "application/wasm"},                           // WebAssembly
	{offset: 257, sig: []byte("ustar"), ext: ".tar", mime: "application/x-tar"},                                         // POSIX TAR
}

// SniffMagicBytes checks the initial byte buffer and refines filename and MIME type.
func SniffMagicBytes(buf []byte, proposedFilename string, proposedMime string) (string, string) {
	if len(buf) == 0 {
		return proposedFilename, proposedMime
	}

	detectedExt := ""
	detectedMime := ""

	// Check custom signature table first
	for _, s := range magicSignatures {
		if len(buf) >= s.offset+len(s.sig) {
			if bytes.Equal(buf[s.offset:s.offset+len(s.sig)], s.sig) {
				detectedExt = s.ext
				detectedMime = s.mime
				break
			}
		}
	}

	// RIFF checks: WEBP or WAV
	if detectedExt == "" && len(buf) >= 12 && bytes.HasPrefix(buf, []byte("RIFF")) {
		riffType := string(buf[8:12])
		if riffType == "WEBP" {
			detectedExt = ".webp"
			detectedMime = "image/webp"
		} else if riffType == "WAVE" {
			detectedExt = ".wav"
			detectedMime = "audio/wav"
		}
	}

	// Fallback to stdlib http.DetectContentType
	if detectedMime == "" {
		stdMime := http.DetectContentType(buf)
		if stdMime != "" && stdMime != "application/octet-stream" {
			detectedMime = stdMime
		}
	}

	finalMime := proposedMime
	if (finalMime == "" || finalMime == "application/octet-stream") && detectedMime != "" {
		finalMime = detectedMime
	}

	finalFilename := proposedFilename
	curExt := strings.ToLower(filepath.Ext(finalFilename))

	// If missing extension or generic placeholder, attach detected extension
	isGenericExt := curExt == "" || curExt == ".bin" || curExt == ".dat" || curExt == ".tmp" || curExt == ".octet-stream"
	if isGenericExt && detectedExt != "" {
		base := strings.TrimSuffix(finalFilename, curExt)
		if base == "" {
			base = "download"
		}
		finalFilename = base + detectedExt
	}

	return finalFilename, finalMime
}

// IsHTMLPayload checks if the initial byte buffer looks like an HTML or XML web document.
func IsHTMLPayload(buf []byte) bool {
	trimmed := bytes.TrimSpace(buf)
	if len(trimmed) == 0 {
		return false
	}
	lower := bytes.ToLower(trimmed)
	return bytes.HasPrefix(lower, []byte("<!doctype html")) ||
		bytes.HasPrefix(lower, []byte("<html")) ||
		bytes.HasPrefix(lower, []byte("<?xml")) ||
		bytes.HasPrefix(lower, []byte("<head")) ||
		bytes.HasPrefix(lower, []byte("<body")) ||
		bytes.HasPrefix(lower, []byte("<script"))
}

// IsBinaryExtension returns true if the filename extension indicates a binary, archive, executable, or media format that should never be HTML.
func IsBinaryExtension(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	switch ext {
	case ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
		".iso", ".dmg", ".img", ".bin",
		".exe", ".msi", ".apk", ".deb", ".rpm",
		".pdf", ".docx", ".xlsx", ".pptx",
		".mp4", ".mkv", ".mp3", ".flac", ".png", ".jpg", ".jpeg", ".gif", ".webp",
		".wasm", ".sqlite", ".sqlite3":
		return true
	}
	return false
}
