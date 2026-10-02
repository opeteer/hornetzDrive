package storage

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestLocalStorage(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ztatic-storage-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	store, err := NewLocalStorageWithConfig(LocalConfig{
		RootDir:    tmpDir,
		ShardDepth: 2,
		BaseURL:    "/uploads",
	})
	if err != nil {
		t.Fatalf("failed to create LocalStorage: %v", err)
	}

	ctx := context.Background()
	content := []byte("Hello Ztatic Local Storage!")
	key := "a1b2c3d4e5f6.txt"

	// 1. Save
	opts := SaveOptions{
		OriginalName: "greeting.txt",
		MIME:         "text/plain",
		Extension:    ".txt",
		SHA256:       "dummy-hash",
	}
	rec, err := store.Save(ctx, key, bytes.NewReader(content), int64(len(content)), opts)
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}
	if rec.Size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), rec.Size)
	}

	// 2. Verify Directory Sharding (key starts with "a1b2", shardDepth=2 -> a1/b2/...)
	expectedSharded := filepath.Join(tmpDir, "a1", "b2", key)
	if _, err := os.Stat(expectedSharded); err != nil {
		t.Errorf("expected sharded file at %s: %v", expectedSharded, err)
	}

	// 3. Exists & Stat
	exists, err := store.Exists(ctx, key)
	if err != nil || !exists {
		t.Errorf("expected file to exist")
	}

	stat, err := store.Stat(ctx, key)
	if err != nil || stat.OriginalName != "greeting.txt" {
		t.Errorf("stat mismatch: %v, %+v", err, stat)
	}

	// 4. Open & Read
	r, rRec, err := store.Open(ctx, key)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer r.Close()

	readBuf := make([]byte, len(content))
	if _, err := r.Read(readBuf); err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if !bytes.Equal(readBuf, content) {
		t.Errorf("content mismatch")
	}
	if rRec.Key != key {
		t.Errorf("record key mismatch")
	}

	// 5. URL
	url, err := store.URL(ctx, key, URLOptions{Download: true})
	if err != nil || !strings.Contains(url, "/uploads/") || !strings.Contains(url, "download=true") {
		t.Errorf("unexpected URL: %s", url)
	}

	// 6. Path Traversal Defense
	_, err = store.Save(ctx, "../../escaped.txt", bytes.NewReader(content), int64(len(content)), opts)
	if err != ErrPathTraversal {
		t.Errorf("expected ErrPathTraversal, got: %v", err)
	}

	// 7. Delete
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	exists, _ = store.Exists(ctx, key)
	if exists {
		t.Errorf("expected file to be deleted")
	}
}

func TestMemoryStorage(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	content := []byte("Memory content buffer")
	key := "mem123.bin"
	opts := SaveOptions{OriginalName: "mem.bin", MIME: "application/octet-stream"}

	// Save
	rec, err := store.Save(ctx, key, bytes.NewReader(content), int64(len(content)), opts)
	if err != nil || rec.Size != int64(len(content)) {
		t.Fatalf("memory save failed: %v", err)
	}

	// Exists & Stat
	exists, _ := store.Exists(ctx, key)
	if !exists {
		t.Errorf("expected memory file to exist")
	}

	stat, err := store.Stat(ctx, key)
	if err != nil || stat.OriginalName != "mem.bin" {
		t.Errorf("stat mismatch")
	}

	// Open
	r, _, err := store.Open(ctx, key)
	if err != nil {
		t.Fatalf("open failed: %v", err)
	}
	defer r.Close()

	buf := make([]byte, len(content))
	_, _ = r.Read(buf)
	if !bytes.Equal(buf, content) {
		t.Errorf("content mismatch")
	}

	// Delete
	_ = store.Delete(ctx, key)
	exists, _ = store.Exists(ctx, key)
	if exists {
		t.Errorf("expected file to be deleted from memory")
	}
}

func TestServeHTTP_HeadersAndRange(t *testing.T) {
	store := NewMemoryStorage()
	ctx := context.Background()

	// Store text file
	textData := []byte("0123456789ABCDEF")
	_, err := store.Save(ctx, "data.txt", bytes.NewReader(textData), int64(len(textData)), SaveOptions{
		OriginalName: "my_data.txt",
		MIME:         "text/plain",
		SHA256:       "sha-1234",
	})
	if err != nil {
		t.Fatalf("failed to save data.txt: %v", err)
	}

	// Store SVG file
	svgData := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><circle r="10"/></svg>`)
	_, err = store.Save(ctx, "image.svg", bytes.NewReader(svgData), int64(len(svgData)), SaveOptions{
		OriginalName: "icon.svg",
		MIME:         "image/svg+xml",
	})
	if err != nil {
		t.Fatalf("failed to save image.svg: %v", err)
	}

	e := echo.New()

	// 1. Test Download Attachment
	req1 := httptest.NewRequest(http.MethodGet, "/files/data.txt", nil)
	rec1 := httptest.NewRecorder()
	c1 := e.NewContext(req1, rec1)

	if err := ServeHTTP(c1, store, "data.txt", WithDownload()); err != nil {
		t.Fatalf("serve failed: %v", err)
	}
	if rec1.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec1.Code)
	}
	if rec1.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected nosniff header")
	}
	if !strings.Contains(rec1.Header().Get("Content-Disposition"), "attachment") {
		t.Errorf("expected attachment Content-Disposition, got: %s", rec1.Header().Get("Content-Disposition"))
	}
	if rec1.Header().Get("ETag") != `"sha-1234"` {
		t.Errorf("expected ETag header")
	}

	// 2. Test Inline SVG with Sandboxed CSP
	req2 := httptest.NewRequest(http.MethodGet, "/files/image.svg", nil)
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)

	if err := ServeHTTP(c2, store, "image.svg", WithInline()); err != nil {
		t.Fatalf("serve inline SVG failed: %v", err)
	}
	if !strings.Contains(rec2.Header().Get("Content-Disposition"), "inline") {
		t.Errorf("expected inline Content-Disposition")
	}
	if rec2.Header().Get("Content-Security-Policy") != "default-src 'none'; sandbox" {
		t.Errorf("expected sandboxed CSP for inline SVG, got: %s", rec2.Header().Get("Content-Security-Policy"))
	}

	// 3. Test HTTP 206 Partial Content (Range: bytes=0-4)
	req3 := httptest.NewRequest(http.MethodGet, "/files/data.txt", nil)
	req3.Header.Set("Range", "bytes=0-4")
	rec3 := httptest.NewRecorder()
	c3 := e.NewContext(req3, rec3)

	if err := ServeHTTP(c3, store, "data.txt"); err != nil {
		t.Fatalf("range request failed: %v", err)
	}
	if rec3.Code != http.StatusPartialContent {
		t.Errorf("expected HTTP 206 Partial Content, got %d", rec3.Code)
	}
	if rec3.Body.String() != "01234" {
		t.Errorf("expected '01234', got %q", rec3.Body.String())
	}
}
