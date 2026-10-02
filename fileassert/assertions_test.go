package fileassert_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/errors"
	"ztatic-go-framework/fileassert"
	"ztatic-go-framework/filetest"
	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
)

func TestFileassert_Suite(t *testing.T) {
	mockStore := filetest.NewMockStorage()
	mockScan := filetest.NewMockScanner()

	// 1. Storage assertions
	fileassert.Missing(t, mockStore, "report.pdf")
	fileassert.FileCount(t, mockStore, 0)

	_, err := mockStore.Save(context.Background(), "report.pdf", strings.NewReader("pdf-content"), 11, storage.SaveOptions{
		OriginalName: "report.pdf",
		MIME:         "application/pdf",
		SHA256:       "abc123sha",
	})
	if err != nil {
		t.Fatalf("save failed: %v", err)
	}

	fileassert.Exists(t, mockStore, "report.pdf")
	fileassert.FileCount(t, mockStore, 1)
	fileassert.Saved(t, mockStore, "report.pdf")
	fileassert.NotSaved(t, mockStore, "other.pdf")
	fileassert.SavedCount(t, mockStore, 1)
	fileassert.ContentString(t, mockStore, "report.pdf", "pdf-content")
	fileassert.ContentEquals(t, mockStore, "report.pdf", []byte("pdf-content"))
	fileassert.Size(t, mockStore, "report.pdf", 11)
	fileassert.MIME(t, mockStore, "report.pdf", "application/pdf")
	fileassert.SHA256(t, mockStore, "report.pdf", "abc123sha")

	_ = mockStore.Delete(context.Background(), "report.pdf")
	fileassert.Deleted(t, mockStore, "report.pdf")
	fileassert.DeletedCount(t, mockStore, 1)

	// 2. Scanner assertions
	fileassert.NotScanned(t, mockScan, "doc.pdf")
	scanRes, _ := mockScan.Scan(context.Background(), strings.NewReader("ok"), 2, scanner.FileInfo{Filename: "doc.pdf"})
	fileassert.ScanClean(t, scanRes)
	fileassert.Scanned(t, mockScan, "doc.pdf")
	fileassert.ScanCount(t, mockScan, 1)

	mockScan.FlagThreat("EICAR-Test-Signature")
	infectedRes, _ := mockScan.Scan(context.Background(), strings.NewReader("virus"), 5, scanner.FileInfo{Filename: "eicar.com"})
	fileassert.ScanInfected(t, infectedRes, "EICAR")

	// 3. Validation & Malware error assertions
	valErr := errors.New("VALIDATION_FAILED", "file_max size exceeded")
	fileassert.ValidationError(t, valErr, "file_max")

	malErr := scanner.NewMalwareError("Heuristic", "Trojan.Fake")
	fileassert.MalwareBlocked(t, malErr, "Trojan.Fake")

	// 4. HTTP response assertions
	e := echo.New()
	e.GET("/file", func(c *echo.Context) error {
		c.Response().Header().Set("Content-Type", "text/plain")
		c.Response().Header().Set("Content-Disposition", `attachment; filename="data.txt"`)
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		c.Response().Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		c.Response().Header().Set("ETag", `"etag-value"`)
		return c.String(http.StatusOK, "hello world")
	})

	client := filetest.NewClient(e)
	resp := client.Get("/file")

	fileassert.Status(t, resp, http.StatusOK)
	fileassert.Downloaded(t, resp, "data.txt")
	fileassert.ContentType(t, resp, "text/plain")
	fileassert.ContentLength(t, resp, 11)
	fileassert.ETag(t, resp, "etag-value")
	fileassert.NoSniff(t, resp)
	fileassert.SandboxedCSP(t, resp)
	fileassert.Checksum(t, resp, resp.SHA256())
}
