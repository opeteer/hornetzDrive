package filetest

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// FileFixture represents a mock or synthetic file for testing uploads and file processing.
type FileFixture interface {
	Name() string
	MIME() string
	Size() int64
	Bytes() []byte
	Reader() io.Reader
	ReaderAt() io.ReaderAt
	SHA256() string
}

// BaseFixture is a standard in-memory implementation of FileFixture.
type BaseFixture struct {
	name   string
	mime   string
	data   []byte
	sha256 string
}

// NewFixture creates a custom BaseFixture with given name, MIME type, and raw byte content.
func NewFixture(name, mime string, data []byte) *BaseFixture {
	h := sha256.Sum256(data)
	return &BaseFixture{
		name:   name,
		mime:   mime,
		data:   data,
		sha256: hex.EncodeToString(h[:]),
	}
}

func (f *BaseFixture) Name() string          { return f.name }
func (f *BaseFixture) MIME() string          { return f.mime }
func (f *BaseFixture) Size() int64           { return int64(len(f.data)) }
func (f *BaseFixture) Bytes() []byte         { return f.data }
func (f *BaseFixture) Reader() io.Reader     { return bytes.NewReader(f.data) }
func (f *BaseFixture) ReaderAt() io.ReaderAt { return bytes.NewReader(f.data) }
func (f *BaseFixture) SHA256() string        { return f.sha256 }

// Fixtures namespace grouping synthetic test file generators.
type Fixtures struct{}

// Default instance of Fixtures for ergonomic access: filetest.Fixture.PNG(...)
var Fixture Fixtures

// -----------------------------------------------------------------------------
// Image Fixtures
// -----------------------------------------------------------------------------

// PNG generates a valid PNG image with the specified dimensions and pixel payload.
// Passes image.DecodeConfig and magic-byte MIME sniffing.
func (Fixtures) PNG(name string, width, height int) FileFixture {
	if width <= 0 {
		width = 1
	}
	if height <= 0 {
		height = 1
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	// Draw a solid color pattern so image has non-zero data
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 50, G: 120, B: 220, A: 255})
		}
	}

	buf := &bytes.Buffer{}
	if err := png.Encode(buf, img); err != nil {
		panic(fmt.Sprintf("filetest: failed to encode PNG: %v", err))
	}
	return NewFixture(name, "image/png", buf.Bytes())
}

// JPEG generates a valid JPEG image with the specified dimensions.
// Passes image.DecodeConfig (SOF0 marker) and magic-byte sniffing.
func (Fixtures) JPEG(name string, width, height int) FileFixture {
	if width <= 0 {
		width = 1
	}
	if height <= 0 {
		height = 1
	}
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, color.RGBA{R: 200, G: 80, B: 80, A: 255})
		}
	}

	buf := &bytes.Buffer{}
	if err := jpeg.Encode(buf, img, &jpeg.Options{Quality: 85}); err != nil {
		panic(fmt.Sprintf("filetest: failed to encode JPEG: %v", err))
	}
	return NewFixture(name, "image/jpeg", buf.Bytes())
}

// GIF generates a valid GIF image with the specified dimensions.
func (Fixtures) GIF(name string, width, height int) FileFixture {
	if width <= 0 {
		width = 1
	}
	if height <= 0 {
		height = 1
	}
	palette := color.Palette{
		color.RGBA{R: 0, G: 0, B: 0, A: 255},
		color.RGBA{R: 255, G: 255, B: 255, A: 255},
	}
	img := image.NewPaletted(image.Rect(0, 0, width, height), palette)

	buf := &bytes.Buffer{}
	if err := gif.Encode(buf, img, nil); err != nil {
		panic(fmt.Sprintf("filetest: failed to encode GIF: %v", err))
	}
	return NewFixture(name, "image/gif", buf.Bytes())
}

// WebP generates a synthetic valid WebP container with proper RIFF headers.
func (Fixtures) WebP(name string) FileFixture {
	// Minimal valid RIFF/WEBP VP8 bitstream header
	raw := []byte{
		'R', 'I', 'F', 'F',
		0x1e, 0x00, 0x00, 0x00, // Size: 30 bytes
		'W', 'E', 'B', 'P',
		'V', 'P', '8', ' ',
		0x12, 0x00, 0x00, 0x00, // Chunk size: 18 bytes
		0x30, 0x01, 0x00, 0x9d, 0x01, 0x2a, 0x01, 0x00, 0x01, 0x00, // 1x1 VP8 frame
		0x02, 0x00, 0x34, 0x25, 0xa4, 0x00, 0x03, 0x70,
	}
	return NewFixture(name, "image/webp", raw)
}

// SVG generates a clean, well-formed SVG vector graphic without scripts.
func (Fixtures) SVG(name string, width, height int, innerXML string) FileFixture {
	if width <= 0 {
		width = 100
	}
	if height <= 0 {
		height = 100
	}
	if innerXML == "" {
		innerXML = `<rect width="100%" height="100%" fill="#4a90e2"/><circle cx="50" cy="50" r="30" fill="#ffffff"/>`
	}
	svgContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d">
%s
</svg>`, width, height, width, height, innerXML)

	return NewFixture(name, "image/svg+xml", []byte(svgContent))
}

// -----------------------------------------------------------------------------
// Document & Structured Data Fixtures
// -----------------------------------------------------------------------------

// PDF synthesizes a valid minimal PDF 1.4 document with catalog, pages, and xref table.
func (Fixtures) PDF(name, textContent string) FileFixture {
	if textContent == "" {
		textContent = "Ztatic Framework Test Document"
	}
	stream := fmt.Sprintf("BT /F1 12 Tf 100 700 Td (%s) Tj ET", textContent)
	streamLen := len(stream)

	pdf := fmt.Sprintf(`%%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length %d >>
stream
%s
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000244 00000 n 
0000000331 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
412
%%%%EOF`, streamLen, stream)

	return NewFixture(name, "application/pdf", []byte(pdf))
}

// Text creates a plain text file fixture.
func (Fixtures) Text(name, content string) FileFixture {
	return NewFixture(name, "text/plain", []byte(content))
}

// CSV creates a formatted CSV file fixture.
func (Fixtures) CSV(name string, rows [][]string) FileFixture {
	buf := &bytes.Buffer{}
	w := csv.NewWriter(buf)
	_ = w.WriteAll(rows)
	w.Flush()
	return NewFixture(name, "text/csv", buf.Bytes())
}

// JSON creates a formatted JSON file fixture.
func (Fixtures) JSON(name string, data any) FileFixture {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("filetest: failed to marshal JSON fixture: %v", err))
	}
	return NewFixture(name, "application/json", b)
}

// -----------------------------------------------------------------------------
// Security & Adversarial Fixtures
// -----------------------------------------------------------------------------

// SVGAttackType defines variants of malicious SVG payloads.
type SVGAttackType int

const (
	SVGAttackScriptTag SVGAttackType = iota
	SVGAttackEventHandler
	SVGAttackJavascriptURI
	SVGAttackXXE
)

// MaliciousSVG generates an SVG containing specific script injection or XXE attacks.
func (Fixtures) MaliciousSVG(name string, attackType SVGAttackType) FileFixture {
	var payload string
	switch attackType {
	case SVGAttackScriptTag:
		payload = `<svg xmlns="http://www.w3.org/2000/svg"><script>alert('xss')</script><circle cx="50" cy="50" r="40"/></svg>`
	case SVGAttackEventHandler:
		payload = `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.cookie)"><circle cx="50" cy="50" r="40"/></svg>`
	case SVGAttackJavascriptURI:
		payload = `<svg xmlns="http://www.w3.org/2000/svg"><a href="javascript:alert(1)"><text x="10" y="20">Click me</text></a></svg>`
	case SVGAttackXXE:
		payload = `<?xml version="1.0" encoding="ISO-8859-1"?>
<!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>`
	}
	return NewFixture(name, "image/svg+xml", []byte(payload))
}

// WebShellType defines web shell payload categories.
type WebShellType int

const (
	WebShellPHP WebShellType = iota
	WebShellJSP
	WebShellASP
)

// WebShell generates a payload containing server-side script execution tags.
func (Fixtures) WebShell(name string, shellType WebShellType) FileFixture {
	var payload string
	var mime string
	switch shellType {
	case WebShellPHP:
		payload = "<?php system($_GET['cmd']); ?>"
		mime = "application/x-httpd-php"
	case WebShellJSP:
		payload = "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"
		mime = "text/x-jsp"
	case WebShellASP:
		payload = "<% eval request(\"cmd\") %>"
		mime = "text/asp"
	}
	return NewFixture(name, mime, []byte(payload))
}

// ExecutableType identifies binary formats.
type ExecutableType int

const (
	ExecutablePE ExecutableType = iota
	ExecutableELF
	ExecutableMachO
)

// Executable generates a minimal binary with authentic executable magic headers.
func (Fixtures) Executable(name string, exeType ExecutableType) FileFixture {
	var raw []byte
	var mime string
	switch exeType {
	case ExecutablePE:
		// Windows PE: MZ header
		raw = []byte{
			0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
			0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		mime = "application/x-dosexec"
	case ExecutableELF:
		// Linux ELF: \x7fELF
		raw = []byte{
			0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x02, 0x00, 0x3E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x50, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		mime = "application/x-executable"
	case ExecutableMachO:
		// macOS Mach-O 64-bit: \xfe\xed\xfa\xcf
		raw = []byte{
			0xFE, 0xED, 0xFA, 0xCF, 0x01, 0x00, 0x00, 0x07, 0x03, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
			0x0B, 0x00, 0x00, 0x00, 0x48, 0x05, 0x00, 0x00, 0x85, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
		mime = "application/x-mach-binary"
	}
	return NewFixture(name, mime, raw)
}

// DisguisedExecutable creates an executable binary bearing an innocent extension (e.g. .png, .jpg, .pdf)
// to test MIME-spoofing detection and heuristic anti-malware scanners.
func (f Fixtures) DisguisedExecutable(name string, exeType ExecutableType) FileFixture {
	fix := f.Executable(name, exeType)
	return NewFixture(name, fix.MIME(), fix.Bytes())
}

// ZipSlip generates an in-memory ZIP archive containing an entry with path traversal (e.g. ../../etc/passwd).
func (Fixtures) ZipSlip(name, maliciousEntry string, payload []byte) FileFixture {
	if maliciousEntry == "" {
		maliciousEntry = "../../../../etc/passwd"
	}
	if len(payload) == 0 {
		payload = []byte("root:x:0:0:root:/root:/bin/bash\n")
	}

	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	header := &zip.FileHeader{
		Name:   maliciousEntry,
		Method: zip.Deflate,
	}
	w, err := zw.CreateHeader(header)
	if err != nil {
		panic(fmt.Sprintf("filetest: failed to create zip entry: %v", err))
	}
	_, _ = w.Write(payload)
	_ = zw.Close()

	return NewFixture(name, "application/zip", buf.Bytes())
}

// ZipBomb generates a zip file with repeated zeros exhibiting an extreme compression ratio.
func (Fixtures) ZipBomb(name string, uncompressedMB int) FileFixture {
	if uncompressedMB <= 0 {
		uncompressedMB = 50
	}
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)

	w, err := zw.CreateHeader(&zip.FileHeader{
		Name:   "zeros.dat",
		Method: zip.Deflate,
	})
	if err != nil {
		panic(err)
	}

	// Write uncompressedMB of zeros in chunks
	chunk := make([]byte, 64*1024)
	total := int64(uncompressedMB) * 1024 * 1024
	var written int64
	for written < total {
		n := int64(len(chunk))
		if total-written < n {
			n = total - written
		}
		_, _ = w.Write(chunk[:n])
		written += n
	}
	_ = zw.Close()

	return NewFixture(name, "application/zip", buf.Bytes())
}

// -----------------------------------------------------------------------------
// Volume & Edge Case Fixtures
// -----------------------------------------------------------------------------

// Oversized produces a virtual streaming fixture representing an arbitrary large file size
// without allocating the bytes in RAM.
func (Fixtures) Oversized(name string, virtualSize int64) FileFixture {
	return &virtualOversizedFixture{
		name: name,
		mime: "application/octet-stream",
		size: virtualSize,
	}
}

type virtualOversizedFixture struct {
	name string
	mime string
	size int64
}

func (v *virtualOversizedFixture) Name() string      { return v.name }
func (v *virtualOversizedFixture) MIME() string      { return v.mime }
func (v *virtualOversizedFixture) Size() int64       { return v.size }
func (v *virtualOversizedFixture) Bytes() []byte     { return nil }
func (v *virtualOversizedFixture) Reader() io.Reader { return io.LimitReader(&infiniteZeroReader{}, v.size) }
func (v *virtualOversizedFixture) ReaderAt() io.ReaderAt {
	return &virtualZeroReaderAt{size: v.size}
}
func (v *virtualOversizedFixture) SHA256() string { return "" }

type infiniteZeroReader struct{}

func (z *infiniteZeroReader) Read(p []byte) (n int, err error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

type virtualZeroReaderAt struct {
	size int64
}

func (z *virtualZeroReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= z.size {
		return 0, io.EOF
	}
	avail := z.size - off
	toRead := int64(len(p))
	if toRead > avail {
		toRead = avail
	}
	for i := int64(0); i < toRead; i++ {
		p[i] = 0
	}
	if toRead < int64(len(p)) {
		return int(toRead), io.EOF
	}
	return int(toRead), nil
}

// Truncated creates a corrupted fixture by truncating bytes from a base fixture.
func (Fixtures) Truncated(base FileFixture, keepBytes int) FileFixture {
	data := base.Bytes()
	if keepBytes > len(data) {
		keepBytes = len(data)
	}
	return NewFixture(base.Name(), base.MIME(), data[:keepBytes])
}

// Empty creates a 0-byte file fixture.
func (Fixtures) Empty(name string) FileFixture {
	return NewFixture(name, "application/octet-stream", []byte{})
}

// -----------------------------------------------------------------------------
// Temporary Filesystem Sandbox
// -----------------------------------------------------------------------------

// Sandbox manages an isolated temporary directory for filesystem testing with LocalStorage.
type Sandbox struct {
	Dir string
	t   testing.TB
}

// TempSandbox creates a managed sandbox tied to the test lifecycle.
func (Fixtures) TempSandbox(t testing.TB) *Sandbox {
	dir := t.TempDir()
	return &Sandbox{Dir: dir, t: t}
}

// WriteFile writes data to a relative path within the sandbox directory.
func (s *Sandbox) WriteFile(relPath string, data []byte) string {
	fullPath := filepath.Join(s.Dir, relPath)
	if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
		s.t.Fatalf("filetest: failed to create sandbox directory: %v", err)
	}
	if err := os.WriteFile(fullPath, data, 0644); err != nil {
		s.t.Fatalf("filetest: failed to write sandbox file %s: %v", relPath, err)
	}
	return fullPath
}

// ReadFile reads the content of a relative file from the sandbox directory.
func (s *Sandbox) ReadFile(relPath string) []byte {
	fullPath := filepath.Join(s.Dir, relPath)
	data, err := os.ReadFile(fullPath)
	if err != nil {
		s.t.Fatalf("filetest: failed to read sandbox file %s: %v", relPath, err)
	}
	return data
}

// Exists checks if a file exists within the sandbox.
func (s *Sandbox) Exists(relPath string) bool {
	fullPath := filepath.Join(s.Dir, relPath)
	_, err := os.Stat(fullPath)
	return err == nil
}

// Subdir creates and returns a subdirectory inside the sandbox.
func (s *Sandbox) Subdir(relPath string) string {
	fullPath := filepath.Join(s.Dir, relPath)
	if err := os.MkdirAll(fullPath, 0755); err != nil {
		s.t.Fatalf("filetest: failed to create subdirectory: %v", err)
	}
	return fullPath
}

// Top-level fixture shortcut functions for convenient 1-line usage:
// filetest.PNG("avatar.png", 200, 200)

func PNG(name string, width, height int) FileFixture { return Fixture.PNG(name, width, height) }
func JPEG(name string, width, height int) FileFixture { return Fixture.JPEG(name, width, height) }
func GIF(name string, width, height int) FileFixture { return Fixture.GIF(name, width, height) }
func WebP(name string) FileFixture { return Fixture.WebP(name) }
func SVG(name string, width, height int, innerXML string) FileFixture {
	return Fixture.SVG(name, width, height, innerXML)
}
func PDF(name, textContent string) FileFixture { return Fixture.PDF(name, textContent) }
func Text(name, content string) FileFixture    { return Fixture.Text(name, content) }
func CSV(name string, rows [][]string) FileFixture { return Fixture.CSV(name, rows) }
func JSON(name string, data any) FileFixture   { return Fixture.JSON(name, data) }
func MaliciousSVG(name string, attackType SVGAttackType) FileFixture {
	return Fixture.MaliciousSVG(name, attackType)
}
func WebShell(name string, shellType WebShellType) FileFixture {
	return Fixture.WebShell(name, shellType)
}
func Executable(name string, exeType ExecutableType) FileFixture {
	return Fixture.Executable(name, exeType)
}
func DisguisedExecutable(name string, exeType ExecutableType) FileFixture {
	return Fixture.DisguisedExecutable(name, exeType)
}
func ZipSlip(name, maliciousEntry string, payload []byte) FileFixture {
	return Fixture.ZipSlip(name, maliciousEntry, payload)
}
func ZipBomb(name string, uncompressedMB int) FileFixture {
	return Fixture.ZipBomb(name, uncompressedMB)
}
func Oversized(name string, virtualSize int64) FileFixture {
	return Fixture.Oversized(name, virtualSize)
}
func Truncated(base FileFixture, keepBytes int) FileFixture {
	return Fixture.Truncated(base, keepBytes)
}
func Empty(name string) FileFixture { return Fixture.Empty(name) }
func TempSandbox(t testing.TB) *Sandbox { return Fixture.TempSandbox(t) }
