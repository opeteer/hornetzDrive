package filetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"ztatic-go-framework/errors"
	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
)

// -----------------------------------------------------------------------------
// Storage Assertions
// -----------------------------------------------------------------------------

// AssertExists asserts that key exists in the storage driver.
func AssertExists(t testing.TB, store storage.Storage, key string) {
	t.Helper()
	exists, err := store.Exists(context.Background(), key)
	if err != nil {
		t.Fatalf("filetest: Exists check failed for key %q: %v", key, err)
	}
	if !exists {
		t.Errorf("expected storage key %q to exist, but was missing", key)
	}
}

// AssertMissing asserts that key does not exist in the storage driver.
func AssertMissing(t testing.TB, store storage.Storage, key string) {
	t.Helper()
	exists, err := store.Exists(context.Background(), key)
	if err != nil {
		t.Fatalf("filetest: Exists check failed for key %q: %v", key, err)
	}
	if exists {
		t.Errorf("expected storage key %q to be missing, but was found", key)
	}
}

// AssertFileCount asserts the total number of files in an in-memory or mock storage.
func AssertFileCount(t testing.TB, store storage.Storage, expected int) {
	t.Helper()
	switch s := store.(type) {
	case *MockStorage:
		if s.StoredCount() != expected {
			t.Errorf("expected %d stored files, got %d", expected, s.StoredCount())
		}
	default:
		t.Fatalf("AssertFileCount requires *MockStorage or supported count-aware storage")
	}
}

// AssertContentEquals opens the file from store and asserts its content matches expectedBytes.
func AssertContentEquals(t testing.TB, store storage.Storage, key string, expectedBytes []byte) {
	t.Helper()
	reader, _, err := store.Open(context.Background(), key)
	if err != nil {
		t.Fatalf("filetest: failed to open key %q: %v", key, err)
	}
	defer reader.Close()

	buf, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("filetest: failed to read stream for key %q: %v", key, err)
	}

	if !bytes.Equal(buf, expectedBytes) {
		t.Errorf("content for key %q does not match expected bytes (len %d vs %d)", key, len(buf), len(expectedBytes))
	}
}

// AssertContentString asserts that the stored file's content matches expectedString.
func AssertContentString(t testing.TB, store storage.Storage, key string, expectedString string) {
	t.Helper()
	AssertContentEquals(t, store, key, []byte(expectedString))
}

// AssertSize asserts the size reported in the file record matches expectedSize.
func AssertSize(t testing.TB, store storage.Storage, key string, expectedSize int64) {
	t.Helper()
	rec, err := store.Stat(context.Background(), key)
	if err != nil {
		t.Fatalf("filetest: failed to stat key %q: %v", key, err)
	}
	if rec.Size != expectedSize {
		t.Errorf("expected size %d for key %q, got %d", expectedSize, key, rec.Size)
	}
}

// AssertMIME asserts the MIME type recorded for key.
func AssertMIME(t testing.TB, store storage.Storage, key string, expectedMIME string) {
	t.Helper()
	rec, err := store.Stat(context.Background(), key)
	if err != nil {
		t.Fatalf("filetest: failed to stat key %q: %v", key, err)
	}
	if rec.MIME != expectedMIME {
		t.Errorf("expected MIME %q for key %q, got %q", expectedMIME, key, rec.MIME)
	}
}

// AssertSHA256 verifies the stored SHA256 matches expectedSHA256, or computes it from content.
func AssertSHA256(t testing.TB, store storage.Storage, key string, expectedSHA256 string) {
	t.Helper()
	rec, err := store.Stat(context.Background(), key)
	if err == nil && rec.SHA256 != "" {
		if rec.SHA256 != expectedSHA256 {
			t.Errorf("expected SHA256 %q for key %q, got %q", expectedSHA256, key, rec.SHA256)
		}
		return
	}

	reader, _, err := store.Open(context.Background(), key)
	if err != nil {
		t.Fatalf("filetest: failed to open key %q: %v", key, err)
	}
	defer reader.Close()

	h := sha256.New()
	if _, err := io.Copy(h, reader); err != nil {
		t.Fatalf("filetest: failed to hash key %q: %v", key, err)
	}
	computed := hex.EncodeToString(h.Sum(nil))
	if computed != expectedSHA256 {
		t.Errorf("expected SHA256 %q for key %q, got %q", expectedSHA256, key, computed)
	}
}

// -----------------------------------------------------------------------------
// HTTP Response Assertions
// -----------------------------------------------------------------------------

// AssertStatus verifies HTTP status code.
func AssertStatus(t testing.TB, resp *Response, expectedCode int) {
	t.Helper()
	resp.AssertStatus(t, expectedCode)
}

// AssertDownloaded asserts attachment download with expected filename.
func AssertDownloaded(t testing.TB, resp *Response, expectedFilename string) {
	t.Helper()
	resp.AssertDownloaded(t, expectedFilename)
}

// AssertInline asserts inline delivery with expected filename.
func AssertInline(t testing.TB, resp *Response, expectedFilename string) {
	t.Helper()
	resp.AssertInline(t, expectedFilename)
}

// AssertContentType asserts Content-Type MIME type.
func AssertContentType(t testing.TB, resp *Response, expectedMIME string) {
	t.Helper()
	resp.AssertContentType(t, expectedMIME)
}

// AssertContentLength asserts Content-Length header or body size.
func AssertContentLength(t testing.TB, resp *Response, expectedLength int64) {
	t.Helper()
	resp.AssertContentLength(t, expectedLength)
}

// AssertETag asserts ETag header value.
func AssertETag(t testing.TB, resp *Response, expectedETag string) {
	t.Helper()
	if resp.ETag() != expectedETag {
		t.Errorf("expected ETag %q, got %q", expectedETag, resp.ETag())
	}
}

// AssertCacheControl asserts Cache-Control header.
func AssertCacheControl(t testing.TB, resp *Response, expected string) {
	t.Helper()
	actual := resp.Header("Cache-Control")
	if actual != expected {
		t.Errorf("expected Cache-Control %q, got %q", expected, actual)
	}
}

// AssertNoSniff asserts X-Content-Type-Options: nosniff header.
func AssertNoSniff(t testing.TB, resp *Response) {
	t.Helper()
	resp.AssertNoSniff(t)
}

// AssertSandboxedCSP asserts Content-Security-Policy contains sandbox.
func AssertSandboxedCSP(t testing.TB, resp *Response) {
	t.Helper()
	resp.AssertSandboxedCSP(t)
}

// AssertAcceptRanges asserts Accept-Ranges: bytes.
func AssertAcceptRanges(t testing.TB, resp *Response) {
	t.Helper()
	resp.AssertAcceptRanges(t)
}

// AssertPartialContent asserts HTTP 206 and matching byte range bounds.
func AssertPartialContent(t testing.TB, resp *Response, start, end, total int64) {
	t.Helper()
	resp.AssertPartialContent(t, start, end, total)
}

// AssertChecksum asserts body SHA256 checksum.
func AssertChecksum(t testing.TB, resp *Response, expectedSHA256 string) {
	t.Helper()
	resp.AssertSHA256(t, expectedSHA256)
}

// -----------------------------------------------------------------------------
// Validation & Security Assertions
// -----------------------------------------------------------------------------

// AssertValidationError asserts that err represents a validation failure involving expectedRule.
func AssertValidationError(t testing.TB, err error, expectedRule string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}

	errStr := err.Error()
	var appErr *errors.Error
	if errors.As(err, &appErr) {
		if appErr.Code == "VALIDATION_FAILED" || strings.Contains(strings.ToLower(appErr.Message), expectedRule) {
			return
		}
		for _, det := range appErr.Details {
			if strings.EqualFold(det.Rule, expectedRule) || strings.Contains(strings.ToLower(det.Field), expectedRule) {
				return
			}
		}
	}

	if !strings.Contains(strings.ToLower(errStr), strings.ToLower(expectedRule)) {
		t.Errorf("expected error to contain validation rule %q, but got: %v", expectedRule, err)
	}
}

// AssertMalwareBlocked asserts that err is a MALWARE_DETECTED error containing expectedThreat.
func AssertMalwareBlocked(t testing.TB, err error, expectedThreat string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected malware error, got nil")
	}

	var appErr *errors.Error
	if errors.As(err, &appErr) {
		if appErr.Code != "MALWARE_DETECTED" {
			t.Errorf("expected error code MALWARE_DETECTED, got %q", appErr.Code)
		}
		if expectedThreat != "" {
			threatMeta, _ := appErr.Metadata["threat"].(string)
			if !strings.Contains(strings.ToLower(appErr.Message), strings.ToLower(expectedThreat)) &&
				!strings.Contains(strings.ToLower(threatMeta), strings.ToLower(expectedThreat)) {
				t.Errorf("expected threat name %q, got message: %s", expectedThreat, appErr.Message)
			}
		}
		return
	}

	if !strings.Contains(err.Error(), expectedThreat) {
		t.Errorf("expected error to mention threat %q, got: %v", expectedThreat, err)
	}
}

// AssertScanClean asserts that scanResult indicates a clean file.
func AssertScanClean(t testing.TB, res *scanner.ScanResult) {
	t.Helper()
	if res == nil {
		t.Fatalf("expected non-nil ScanResult")
	}
	if !res.Clean {
		t.Errorf("expected scan result to be clean, but threat was flagged: %s", res.ThreatName)
	}
}

// AssertScanInfected asserts that scanResult indicates an infected file matching expectedThreat.
func AssertScanInfected(t testing.TB, res *scanner.ScanResult, expectedThreat string) {
	t.Helper()
	if res == nil {
		t.Fatalf("expected non-nil ScanResult")
	}
	if res.Clean {
		t.Errorf("expected scan result to be infected, but was marked clean")
	}
	if expectedThreat != "" && !strings.Contains(strings.ToLower(res.ThreatName), strings.ToLower(expectedThreat)) {
		t.Errorf("expected threat %q, got %q", expectedThreat, res.ThreatName)
	}
}

// -----------------------------------------------------------------------------
// Mock Spy Assertions
// -----------------------------------------------------------------------------

// AssertSaved asserts that Save was invoked on mockStore with key.
func AssertSaved(t testing.TB, store *MockStorage, key string) {
	t.Helper()
	if !store.WasSaved(key) {
		t.Errorf("expected key %q to have been saved to MockStorage, but was not", key)
	}
}

// AssertNotSaved asserts that Save was never invoked on mockStore with key.
func AssertNotSaved(t testing.TB, store *MockStorage, key string) {
	t.Helper()
	if store.WasSaved(key) {
		t.Errorf("expected key %q NOT to have been saved to MockStorage, but was", key)
	}
}

// AssertDeleted asserts that Delete was invoked on mockStore with key.
func AssertDeleted(t testing.TB, store *MockStorage, key string) {
	t.Helper()
	if !store.WasDeleted(key) {
		t.Errorf("expected key %q to have been deleted from MockStorage, but was not", key)
	}
}

// AssertSavedCount asserts the number of Save calls on mockStore.
func AssertSavedCount(t testing.TB, store *MockStorage, expectedCount int) {
	t.Helper()
	if store.SaveCallCount() != expectedCount {
		t.Errorf("expected %d Save calls, got %d", expectedCount, store.SaveCallCount())
	}
}

// AssertDeletedCount asserts the number of Delete calls on mockStore.
func AssertDeletedCount(t testing.TB, store *MockStorage, expectedCount int) {
	t.Helper()
	if store.DeleteCallCount() != expectedCount {
		t.Errorf("expected %d Delete calls, got %d", expectedCount, store.DeleteCallCount())
	}
}

// AssertScanned asserts that filename was inspected by mockScanner.
func AssertScanned(t testing.TB, scanner *MockScanner, filename string) {
	t.Helper()
	if !scanner.WasScanned(filename) {
		t.Errorf("expected filename %q to have been scanned by MockScanner, but was not", filename)
	}
}

// AssertNotScanned asserts that filename was NOT inspected by mockScanner.
func AssertNotScanned(t testing.TB, scanner *MockScanner, filename string) {
	t.Helper()
	if scanner.WasScanned(filename) {
		t.Errorf("expected filename %q NOT to have been scanned by MockScanner, but was", filename)
	}
}

// AssertScanCount asserts the number of scans performed by mockScanner.
func AssertScanCount(t testing.TB, scanner *MockScanner, expectedCount int) {
	t.Helper()
	if scanner.ScanCount() != expectedCount {
		t.Errorf("expected %d scan invocations, got %d", expectedCount, scanner.ScanCount())
	}
}
