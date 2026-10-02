package upload

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
)

// Valid 1x1 PNG bytes for testing
var validPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
	0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
	0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"normal.png", "normal.png"},
		{"../../etc/passwd", "passwd"},
		{"..\\..\\windows\\system32\\calc.exe", "calc.exe"},
		{"photo\x00.jpg", "photo.jpg"},
		{"my document (1) [final] & special.pdf", "my_document_1_final_special.pdf"},
		{"CON.png", "safe_CON.png"},
		{"COM1.txt", "safe_COM1.txt"},
		{"...hidden...file...", "hidden...file"},
		{"", "unnamed_file"},
	}

	for _, tt := range tests {
		got := SanitizeFilename(tt.input)
		if got != tt.expected {
			t.Errorf("SanitizeFilename(%q) = %q; want %q", tt.input, got, tt.expected)
		}
	}
}

func TestGenerateStorageKey(t *testing.T) {
	content := []byte("hello storage key")

	keyUUID := GenerateStorageKey(StrategyUUID, "avatar.png", content, nil)
	if !strings.HasSuffix(keyUUID, ".png") || len(keyUUID) < 36 {
		t.Errorf("unexpected UUID key: %s", keyUUID)
	}

	keyULID := GenerateStorageKey(StrategyULID, "avatar.png", content, nil)
	if !strings.HasSuffix(keyULID, ".png") {
		t.Errorf("unexpected ULID key: %s", keyULID)
	}

	keyHash := GenerateStorageKey(StrategySHA256, "avatar.png", content, nil)
	if !strings.HasSuffix(keyHash, ".png") || len(keyHash) != 64+4 {
		t.Errorf("unexpected SHA256 key: %s", keyHash)
	}

	keyOrig := GenerateStorageKey(StrategyOriginalSanitized, "my_avatar.png", content, nil)
	if !strings.HasPrefix(keyOrig, "my_avatar_") || !strings.HasSuffix(keyOrig, ".png") {
		t.Errorf("unexpected sanitized key: %s", keyOrig)
	}
}

func TestValidator_SizeBounds(t *testing.T) {
	val := NewValidator().MaxBytes(100).MinBytes(10).AllowedMIMEs("text/plain").AllowedExtensions(".txt")

	// Valid size
	rOk := strings.NewReader("12345678901234567890")
	_, err := val.ValidateReader(context.Background(), rOk, int64(rOk.Len()), "test.txt")
	if err != nil {
		t.Errorf("expected valid size to pass, got: %v", err)
	}

	// Too small
	rSmall := strings.NewReader("123")
	_, err = val.ValidateReader(context.Background(), rSmall, int64(rSmall.Len()), "small.txt")
	if err == nil {
		t.Errorf("expected size too small error")
	}

	// Too large
	largeData := make([]byte, 150)
	rLarge := bytes.NewReader(largeData)
	_, err = val.ValidateReader(context.Background(), rLarge, int64(len(largeData)), "large.txt")
	if err == nil {
		t.Errorf("expected size too large error")
	}
}

func TestValidator_MagicBytesSniffingAndSpoofing(t *testing.T) {
	val := NewValidator().
		AllowedMIMEs("image/png", "image/jpeg").
		AllowedExtensions(".png", ".jpg", ".jpeg")

	ctx := context.Background()

	// 1. Valid PNG
	rPNG := bytes.NewReader(validPNG)
	res, err := val.ValidateReader(ctx, rPNG, int64(len(validPNG)), "avatar.png")
	if err != nil {
		t.Fatalf("expected valid PNG to pass: %v", err)
	}
	if res.MIME != "image/png" {
		t.Errorf("expected MIME image/png, got %s", res.MIME)
	}
	if res.Width != 1 || res.Height != 1 {
		t.Errorf("expected 1x1 dimensions, got %dx%d", res.Width, res.Height)
	}

	// 2. Disguised executable named .png
	peData := []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
	rPE := bytes.NewReader(peData)
	_, err = val.ValidateReader(ctx, rPE, int64(len(peData)), "disguised.png")
	if err == nil {
		t.Errorf("expected disguised executable to be rejected")
	}

	// 3. Disallowed extension
	_, err = val.ValidateReader(ctx, rPNG, int64(len(validPNG)), "avatar.exe")
	if err == nil {
		t.Errorf("expected disallowed extension to be rejected")
	}
}

func TestValidator_ImageDimensions(t *testing.T) {
	val := NewValidator().
		MaxDimensions(100, 100).
		MinDimensions(2, 2) // 1x1 will fail min dimensions

	rPNG := bytes.NewReader(validPNG)
	_, err := val.ValidateReader(context.Background(), rPNG, int64(len(validPNG)), "image.png")
	if err == nil {
		t.Errorf("expected 1x1 image to fail MinDimensions (2x2)")
	}
}

func TestUploadManager_EndToEnd(t *testing.T) {
	memStore := storage.NewMemoryStorage()
	heurScanner := scanner.NewHeuristicScanner()

	cfg := Config{
		MaxFileSize:       5 * MB,
		AllowedMIMEs:      ImageMIMEs(),
		AllowedExtensions: ImageExtensions(),
		NamingStrategy:    StrategyUUID,
		Scanner:           heurScanner,
		Storage:           memStore,
	}

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatalf("failed to create manager: %v", err)
	}

	// Create multipart request
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("avatar", "profile.png")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write(validPNG)
	_ = writer.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	processed, err := mgr.Process(c, "avatar")
	if err != nil {
		t.Fatalf("expected successful upload, got: %v", err)
	}

	if processed.OriginalName != "profile.png" {
		t.Errorf("expected original name profile.png, got: %s", processed.OriginalName)
	}
	if processed.MIME != "image/png" {
		t.Errorf("expected image/png MIME, got: %s", processed.MIME)
	}
	exists, _ := memStore.Exists(context.Background(), processed.Key)
	if !exists {
		t.Errorf("expected file to exist in memory storage")
	}
}

func TestUploadManager_MalwareInterception(t *testing.T) {
	memStore := storage.NewMemoryStorage()
	heurScanner := scanner.NewHeuristicScanner()

	cfg := Config{
		MaxFileSize:       5 * MB,
		AllowedMIMEs:      []string{"image/svg+xml"},
		AllowedExtensions: []string{".svg"},
		Scanner:           heurScanner,
		Storage:           memStore,
	}

	mgr, _ := NewManager(cfg)

	// SVG containing malicious JavaScript
	maliciousSVG := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert("XSS")</script></svg>`)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("logo", "vector.svg")
	_, _ = part.Write(maliciousSVG)
	_ = writer.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	_, err := mgr.Process(c, "logo")
	if err == nil {
		t.Fatalf("expected malware error, got success")
	}
	if !strings.Contains(err.Error(), "Malware detected") {
		t.Errorf("expected malware error message, got: %v", err)
	}
}

func TestUploadMiddleware_RouteLimit(t *testing.T) {
	e := echo.New()

	e.POST("/upload", func(c *echo.Context) error {
		return c.String(http.StatusOK, "uploaded")
	}, RouteLimit(50)) // limit to 50 bytes

	// Payload within limit
	reqSmall := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader("small payload"))
	reqSmall.Header.Set("Content-Length", fmt.Sprintf("%d", len("small payload")))
	recSmall := httptest.NewRecorder()
	e.ServeHTTP(recSmall, reqSmall)
	if recSmall.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", recSmall.Code)
	}

	// Payload exceeding limit
	largePayload := strings.Repeat("A", 100)
	reqLarge := httptest.NewRequest(http.MethodPost, "/upload", strings.NewReader(largePayload))
	reqLarge.Header.Set("Content-Length", fmt.Sprintf("%d", len(largePayload)))
	recLarge := httptest.NewRecorder()
	e.ServeHTTP(recLarge, reqLarge)
	if recLarge.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("expected 413, got %d", recLarge.Code)
	}
}

func TestUploadManager_LocalStorageIntegration(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "upload-local-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	localStore, err := storage.NewLocalStorage(tmpDir)
	if err != nil {
		t.Fatalf("failed to create LocalStorage: %v", err)
	}

	cfg := Config{
		MaxFileSize:       2 * MB,
		AllowedMIMEs:      ImageMIMEs(),
		AllowedExtensions: ImageExtensions(),
		Storage:           localStore,
	}

	mgr, _ := NewManager(cfg)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", "image.png")
	_, _ = part.Write(validPNG)
	_ = writer.Close()

	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	proc, err := mgr.Process(c, "file")
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}

	exists, err := localStore.Exists(context.Background(), proc.Key)
	if err != nil || !exists {
		t.Errorf("file should exist on local disk")
	}

	// Verify file content on disk matches
	readCloser, _, err := localStore.Open(context.Background(), proc.Key)
	if err != nil {
		t.Fatalf("open local file failed: %v", err)
	}
	defer readCloser.Close()

	readData, err := io.ReadAll(readCloser)
	if err != nil || !bytes.Equal(readData, validPNG) {
		t.Errorf("disk content does not match uploaded PNG")
	}
}
