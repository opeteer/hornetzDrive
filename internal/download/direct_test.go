package download

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/realtime"
)

func TestParseFilenameFromHeaders(t *testing.T) {
	tests := []struct {
		header   string
		rawURL   string
		expected string
	}{
		{`attachment; filename="data.csv"`, "http://example.com/item", "data.csv"},
		{`attachment; filename*=UTF-8''my%20presentation.pptx`, "http://example.com/doc", "my presentation.pptx"},
		{`inline; filename="avatar.png"`, "http://example.com/pic", "avatar.png"},
		{"", "https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso", "ubuntu-24.04-desktop-amd64.iso"},
		{"", "https://example.com/download?id=123", "download"},
	}

	for _, tt := range tests {
		got := ParseFilenameFromHeaders(tt.header, tt.rawURL)
		if got != tt.expected {
			t.Errorf("ParseFilenameFromHeaders(%q, %q) = %q; expected %q", tt.header, tt.rawURL, got, tt.expected)
		}
	}
}

func TestDirectDownloader_DownloadDirect(t *testing.T) {
	content := []byte("Hello, this is a direct downloaded payload from Hornetz Drive!")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="test_doc.txt"`)
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer ts.Close()

	dd := NewDirectDownloader()
	var dest bytes.Buffer
	var progressReports int

	info, err := dd.DownloadDirect(context.Background(), ts.URL+"/file", &dest, func(downloaded, total int64, speed string) {
		progressReports++
	})
	if err != nil {
		t.Fatalf("DownloadDirect error: %v", err)
	}

	if info.Filename != "test_doc.txt" {
		t.Errorf("Expected filename 'test_doc.txt', got %q", info.Filename)
	}
	if info.MimeType != "text/plain" {
		t.Errorf("Expected mime_type 'text/plain', got %q", info.MimeType)
	}
	if info.TotalBytes != int64(len(content)) {
		t.Errorf("Expected TotalBytes %d, got %d", len(content), info.TotalBytes)
	}
	if dest.String() != string(content) {
		t.Errorf("Downloaded content mismatch: got %q", dest.String())
	}
}

func TestDownloadManager_DirectDownloadLifecycle(t *testing.T) {
	fileData := []byte("Encrypted CAS stored content via DownloadManager direct download test!")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="managed_payload.dat"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileData)
	}))
	defer ts.Close()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to init memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, salt BLOB, encrypted_vault_key BLOB);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER, parent_id TEXT, name TEXT);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER, folder_id TEXT, name TEXT, mime_type TEXT, size BIGINT, cas_hash TEXT, plaintext_hash TEXT, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatalf("Schema init failed: %v", err)
	}

	casDir := t.TempDir()
	casEngine, err := storage.NewCASEngine(casDir)
	if err != nil {
		t.Fatalf("CAS init failed: %v", err)
	}

	broker := realtime.NewMemoryBroker()
	mgr, err := NewDownloadManager(casEngine, dbEngine, broker, t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewDownloadManager failed: %v", err)
	}

	task, err := mgr.StartDownload(context.Background(), 1, "root", ts.URL+"/managed_payload.dat", false, nil)
	if err != nil {
		t.Fatalf("StartDownload failed: %v", err)
	}

	if task.ID == "" {
		t.Fatalf("Expected non-empty task ID")
	}

	// Poll until completed (with 5 second timeout)
	deadline := time.Now().Add(5 * time.Second)
	var finalTask *DownloadTask
	for time.Now().Before(deadline) {
		tSnap, found := mgr.GetTask(task.ID)
		if found && (tSnap.Status == StatusCompleted || tSnap.Status == StatusFailed) {
			finalTask = tSnap
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if finalTask == nil || finalTask.Status != StatusCompleted {
		errMsg := ""
		if finalTask != nil {
			errMsg = finalTask.ErrorMessage
		}
		t.Fatalf("Download did not complete successfully. Status: %v, error: %s", finalTask, errMsg)
	}

	if finalTask.Filename != "managed_payload.dat" {
		t.Errorf("Expected filename 'managed_payload.dat', got %q", finalTask.Filename)
	}

	if finalTask.CasHash == "" {
		t.Fatalf("Expected CasHash to be set")
	}

	// Verify file is stored in CAS
	if !casEngine.Exists(finalTask.CasHash) {
		t.Fatalf("File does not exist in CAS at hash %s", finalTask.CasHash)
	}

	// Verify file record in database
	var count int
	var storedName, storedCas string
	err = dbEngine.SQL.QueryRow("SELECT COUNT(*), name, cas_hash FROM files WHERE id = ?", finalTask.FileID).Scan(&count, &storedName, &storedCas)
	if err != nil || count != 1 {
		t.Fatalf("DB query failed: %v, count: %d", err, count)
	}

	if storedName != "managed_payload.dat" || storedCas != finalTask.CasHash {
		t.Errorf("DB record mismatch: name=%s, cas=%s", storedName, storedCas)
	}
}
