package fileassert

import (
	"testing"

	"ztatic-go-framework/filetest"
	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
)

// Storage Assertions

func Exists(t testing.TB, store storage.Storage, key string) {
	t.Helper()
	filetest.AssertExists(t, store, key)
}

func Missing(t testing.TB, store storage.Storage, key string) {
	t.Helper()
	filetest.AssertMissing(t, store, key)
}

func FileCount(t testing.TB, store storage.Storage, expected int) {
	t.Helper()
	filetest.AssertFileCount(t, store, expected)
}

func ContentEquals(t testing.TB, store storage.Storage, key string, expectedBytes []byte) {
	t.Helper()
	filetest.AssertContentEquals(t, store, key, expectedBytes)
}

func ContentString(t testing.TB, store storage.Storage, key string, expectedString string) {
	t.Helper()
	filetest.AssertContentString(t, store, key, expectedString)
}

func Size(t testing.TB, store storage.Storage, key string, expectedSize int64) {
	t.Helper()
	filetest.AssertSize(t, store, key, expectedSize)
}

func MIME(t testing.TB, store storage.Storage, key string, expectedMIME string) {
	t.Helper()
	filetest.AssertMIME(t, store, key, expectedMIME)
}

func SHA256(t testing.TB, store storage.Storage, key string, expectedSHA256 string) {
	t.Helper()
	filetest.AssertSHA256(t, store, key, expectedSHA256)
}

// HTTP Response Assertions

func Status(t testing.TB, resp *filetest.Response, expectedCode int) {
	t.Helper()
	filetest.AssertStatus(t, resp, expectedCode)
}

func Downloaded(t testing.TB, resp *filetest.Response, expectedFilename string) {
	t.Helper()
	filetest.AssertDownloaded(t, resp, expectedFilename)
}

func Inline(t testing.TB, resp *filetest.Response, expectedFilename string) {
	t.Helper()
	filetest.AssertInline(t, resp, expectedFilename)
}

func ContentType(t testing.TB, resp *filetest.Response, expectedMIME string) {
	t.Helper()
	filetest.AssertContentType(t, resp, expectedMIME)
}

func ContentLength(t testing.TB, resp *filetest.Response, expectedLength int64) {
	t.Helper()
	filetest.AssertContentLength(t, resp, expectedLength)
}

func ETag(t testing.TB, resp *filetest.Response, expectedETag string) {
	t.Helper()
	filetest.AssertETag(t, resp, expectedETag)
}

func CacheControl(t testing.TB, resp *filetest.Response, expected string) {
	t.Helper()
	filetest.AssertCacheControl(t, resp, expected)
}

func NoSniff(t testing.TB, resp *filetest.Response) {
	t.Helper()
	filetest.AssertNoSniff(t, resp)
}

func SandboxedCSP(t testing.TB, resp *filetest.Response) {
	t.Helper()
	filetest.AssertSandboxedCSP(t, resp)
}

func AcceptRanges(t testing.TB, resp *filetest.Response) {
	t.Helper()
	filetest.AssertAcceptRanges(t, resp)
}

func PartialContent(t testing.TB, resp *filetest.Response, start, end, total int64) {
	t.Helper()
	filetest.AssertPartialContent(t, resp, start, end, total)
}

func Checksum(t testing.TB, resp *filetest.Response, expectedSHA256 string) {
	t.Helper()
	filetest.AssertChecksum(t, resp, expectedSHA256)
}

// Validation & Security Assertions

func ValidationError(t testing.TB, err error, expectedRule string) {
	t.Helper()
	filetest.AssertValidationError(t, err, expectedRule)
}

func MalwareBlocked(t testing.TB, err error, expectedThreat string) {
	t.Helper()
	filetest.AssertMalwareBlocked(t, err, expectedThreat)
}

func ScanClean(t testing.TB, res *scanner.ScanResult) {
	t.Helper()
	filetest.AssertScanClean(t, res)
}

func ScanInfected(t testing.TB, res *scanner.ScanResult, expectedThreat string) {
	t.Helper()
	filetest.AssertScanInfected(t, res, expectedThreat)
}

// Mock Interaction Assertions

func Saved(t testing.TB, store *filetest.MockStorage, key string) {
	t.Helper()
	filetest.AssertSaved(t, store, key)
}

func NotSaved(t testing.TB, store *filetest.MockStorage, key string) {
	t.Helper()
	filetest.AssertNotSaved(t, store, key)
}

func Deleted(t testing.TB, store *filetest.MockStorage, key string) {
	t.Helper()
	filetest.AssertDeleted(t, store, key)
}

func SavedCount(t testing.TB, store *filetest.MockStorage, expectedCount int) {
	t.Helper()
	filetest.AssertSavedCount(t, store, expectedCount)
}

func DeletedCount(t testing.TB, store *filetest.MockStorage, expectedCount int) {
	t.Helper()
	filetest.AssertDeletedCount(t, store, expectedCount)
}

func Scanned(t testing.TB, scan *filetest.MockScanner, filename string) {
	t.Helper()
	filetest.AssertScanned(t, scan, filename)
}

func NotScanned(t testing.TB, scan *filetest.MockScanner, filename string) {
	t.Helper()
	filetest.AssertNotScanned(t, scan, filename)
}

func ScanCount(t testing.TB, scan *filetest.MockScanner, expectedCount int) {
	t.Helper()
	filetest.AssertScanCount(t, scan, expectedCount)
}
