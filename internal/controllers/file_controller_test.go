package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/labstack/echo/v5"
	_ "github.com/mattn/go-sqlite3"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"
)

func TestFileController_GetFiles_AfterUpload(t *testing.T) {
	e := echo.New()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	// Run migrations
	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	casEngine, _ := storage.NewCASEngine(t.TempDir())
	fileCtrl := &FileController{
		DB:  dbEngine,
		CAS: casEngine,
	}
	fileCtrl.SeedInitialData()

	// Simulate upload insertion as done in UploadChunk
	fileID := "file_uploaded_123"
	_, err = dbEngine.SQL.Exec("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES (?, 1, 'f1', 'test_doc.pdf', 'application/pdf', 1024, 'abc123hash')", fileID)
	if err != nil {
		t.Fatalf("Failed to insert file: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/files?tab=storage", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := fileCtrl.GetFiles(c); err != nil {
		t.Fatalf("GetFiles returned error: %v", err)
	}

	var files []FileRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &files); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	t.Logf("Retrieved %d files: %+v", len(files), files)
	foundUploaded := false
	for _, f := range files {
		if f.ID == fileID {
			foundUploaded = true
			break
		}
	}

	if !foundUploaded {
		t.Fatalf("Uploaded file %s was not found in GetFiles response! Total files returned: %d", fileID, len(files))
	}
}

func TestFileController_GetFiles_FolderAndVaultFiltering(t *testing.T) {
	e := echo.New()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	`)

	casEngine, _ := storage.NewCASEngine(t.TempDir())
	fileCtrl := &FileController{
		DB:  dbEngine,
		CAS: casEngine,
	}
	fileCtrl.SeedInitialData()

	// 1. Test folder filtering: folder_id=f3 should only return files in folder f3
	reqF3 := httptest.NewRequest(http.MethodGet, "/api/files?folder_id=f3", nil)
	recF3 := httptest.NewRecorder()
	cF3 := e.NewContext(reqF3, recF3)
	if err := fileCtrl.GetFiles(cF3); err != nil {
		t.Fatalf("GetFiles error: %v", err)
	}
	var filesF3 []FileRecord
	json.Unmarshal(recF3.Body.Bytes(), &filesF3)
	if len(filesF3) != 2 {
		t.Fatalf("Expected 2 files for folder_id=f3, got %d", len(filesF3))
	}
	for _, f := range filesF3 {
		if f.FolderID != "f3" {
			t.Fatalf("Expected folder_id f3, got %s for file %s", f.FolderID, f.Name)
		}
	}

	// 2. Test vault tab filtering: tab=vault should return vault files (folder_id=f2)
	reqVault := httptest.NewRequest(http.MethodGet, "/api/files?tab=vault", nil)
	recVault := httptest.NewRecorder()
	cVault := e.NewContext(reqVault, recVault)
	if err := fileCtrl.GetFiles(cVault); err != nil {
		t.Fatalf("GetFiles error: %v", err)
	}
	var filesVault []FileRecord
	json.Unmarshal(recVault.Body.Bytes(), &filesVault)
	if len(filesVault) == 0 {
		t.Fatalf("Expected at least 1 vault file for tab=vault")
	}
	for _, f := range filesVault {
		if f.FolderID != "f2" && f.MimeType != "application/octet-stream" {
			t.Fatalf("Unexpected file in vault tab: %+v", f)
		}
	}
}

func TestFileController_GetStorageStats(t *testing.T) {
	e := echo.New()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	casEngine, _ := storage.NewCASEngine(t.TempDir())
	fileCtrl := &FileController{
		DB:  dbEngine,
		CAS: casEngine,
	}
	fileCtrl.SeedInitialData()

	req := httptest.NewRequest(http.MethodGet, "/api/storage/stats", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := fileCtrl.GetStorageStats(c); err != nil {
		t.Fatalf("GetStorageStats error: %v", err)
	}

	var stats StorageStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("Failed to unmarshal storage stats: %v", err)
	}

	if stats.UsedBytes <= 0 {
		t.Fatalf("Expected used_bytes > 0, got %d", stats.UsedBytes)
	}
	if stats.FileCount != 4 {
		t.Fatalf("Expected 4 files, got %d", stats.FileCount)
	}
	if stats.QuotaFormatted != "2 TB" {
		t.Fatalf("Expected quota_formatted '2 TB', got %s", stats.QuotaFormatted)
	}
	if stats.PercentUsed <= 0 || stats.PercentUsed > 100 {
		t.Fatalf("Invalid percent_used: %f", stats.PercentUsed)
	}
}

func TestFileController_DownloadFile_ContentLengthAndDecryption(t *testing.T) {
	e := echo.New()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size INTEGER NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
	`)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	casDir := t.TempDir()
	casEngine, err := storage.NewCASEngine(casDir)
	if err != nil {
		t.Fatalf("NewCASEngine failed: %v", err)
	}

	fileCtrl := &FileController{
		DB:  dbEngine,
		CAS: casEngine,
	}

	// 1. Test fallback mock file download (Content-Length header)
	_, _ = dbEngine.SQL.Exec("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES ('mock_1', 1, 'f1', 'mock.txt', 'text/plain', 500, 'nonexistent_cas')")
	e.GET("/api/files/:id/download", fileCtrl.DownloadFile)

	req := httptest.NewRequest(http.MethodGet, "/api/files/mock_1/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DownloadFile mock returned status %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Length") != "500" {
		t.Errorf("Expected Content-Length 500, got %q", rec.Header().Get("Content-Length"))
	}
	if rec.Header().Get("Content-Disposition") != `attachment; filename="mock.txt"` {
		t.Errorf("Unexpected Content-Disposition: %q", rec.Header().Get("Content-Disposition"))
	}

	// 2. Test downloading real CAS-stored encrypted file with io.Copy
	secretData := []byte("Swarm encrypted payload for download verification - 1234567890")
	tempRawFile := casDir + "/temp_raw.bin"
	_ = os.WriteFile(tempRawFile, secretData, 0644)

	// Encrypt to temp file
	tempEncFile := casDir + "/temp_enc.bin"
	encF, _ := os.Create(tempEncFile)
	encWriter, _ := crypto.NewEncryptStream(encF, crypto.DummyVK())
	_, _ = encWriter.Write(secretData)
	_ = encF.Close()

	casHash, err := casEngine.MoveToCAS(tempEncFile)
	if err != nil {
		t.Fatalf("MoveToCAS failed: %v", err)
	}

	_, _ = dbEngine.SQL.Exec("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES ('real_cas_1', 1, 'f1', 'secret.txt', 'text/plain', ?, ?)", len(secretData), casHash)

	req2 := httptest.NewRequest(http.MethodGet, "/api/files/real_cas_1/download", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("DownloadFile CAS returned status %d: %s", rec2.Code, rec2.Body.String())
	}
	if rec2.Header().Get("Content-Length") != strconv.Itoa(len(secretData)) {
		t.Errorf("Expected Content-Length %d, got %q", len(secretData), rec2.Header().Get("Content-Length"))
	}
	if !bytes.Equal(rec2.Body.Bytes(), secretData) {
		t.Errorf("Downloaded decrypted content %q does not match original %q", rec2.Body.String(), string(secretData))
	}
}
