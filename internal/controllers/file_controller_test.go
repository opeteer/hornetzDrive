package controllers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	_ "github.com/mattn/go-sqlite3"

	"ztatic-go-framework/data"
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
