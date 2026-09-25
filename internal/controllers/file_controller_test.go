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
