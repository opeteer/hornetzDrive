package download

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProbeLink_StandardHEAD(t *testing.T) {
	orig := AllowPrivateNetworks
	AllowPrivateNetworks = true
	defer func() { AllowPrivateNetworks = orig }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="annual_report.pdf"`)
		w.Header().Set("Content-Type", "application/pdf")
		w.Header().Set("Content-Length", "2097152") // 2 MB
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	res, err := ProbeLink(context.Background(), ts.Client(), ts.URL+"/report")
	if err != nil {
		t.Fatalf("ProbeLink failed: %v", err)
	}

	if res.Filename != "annual_report.pdf" {
		t.Errorf("Expected filename 'annual_report.pdf', got %q", res.Filename)
	}
	if res.FileSize != 2097152 {
		t.Errorf("Expected file size 2097152, got %d", res.FileSize)
	}
	if res.Category != "document" {
		t.Errorf("Expected category 'document', got %q", res.Category)
	}
	if !res.Resumable {
		t.Errorf("Expected resumable=true")
	}
}

func TestProbeLink_HeadFallbackToGetRange(t *testing.T) {
	orig := AllowPrivateNetworks
	AllowPrivateNetworks = true
	defer func() { AllowPrivateNetworks = orig }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// Simulate servers that forbid HEAD requests (e.g. S3 or certain CDNs)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Disposition", `attachment; filename="data_export.zip"`)
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Range", "bytes 0-0/10485760") // 10 MB
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte("P"))
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	res, err := ProbeLink(context.Background(), ts.Client(), ts.URL+"/export")
	if err != nil {
		t.Fatalf("ProbeLink fallback failed: %v", err)
	}

	if res.Filename != "data_export.zip" {
		t.Errorf("Expected filename 'data_export.zip', got %q", res.Filename)
	}
	if res.FileSize != 10485760 {
		t.Errorf("Expected file size 10485760, got %d", res.FileSize)
	}
	if res.Category != "archive" {
		t.Errorf("Expected category 'archive', got %q", res.Category)
	}
	if !res.Resumable {
		t.Errorf("Expected resumable=true for HTTP 206")
	}
}

func TestProbeLink_BatchAndMagnet(t *testing.T) {
	// 1. Batch input
	batchInput := "https://example.com/chunk_[1-3].bin"
	resBatch, err := ProbeLink(context.Background(), nil, batchInput)
	if err != nil {
		t.Fatalf("ProbeLink batch failed: %v", err)
	}
	if !resBatch.IsBatch || resBatch.BatchCount != 3 {
		t.Errorf("Expected batch with 3 items, got %+v", resBatch)
	}

	// 2. Magnet link
	magInput := "magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=linux_distro.iso"
	resMag, err := ProbeLink(context.Background(), nil, magInput)
	if err != nil {
		t.Fatalf("ProbeLink magnet failed: %v", err)
	}
	if resMag.Type != DownloadTypeMagnet || resMag.Filename != "linux_distro.iso" {
		t.Errorf("Expected magnet probe result, got %+v", resMag)
	}
}
