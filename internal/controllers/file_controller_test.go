package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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
	expectedLen := strconv.Itoa(len(rec.Body.String()))
	if rec.Header().Get("Content-Length") != expectedLen {
		t.Errorf("Expected Content-Length %s matching body, got %q", expectedLen, rec.Header().Get("Content-Length"))
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

func TestFileController_DeleteRestoreAndStar(t *testing.T) {
	e := echo.New()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, is_starred BOOLEAN DEFAULT 0, is_deleted BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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

	// Insert test CAS file
	tmpFile := filepath.Join(casDir, "temp_upload.bin")
	if err := os.WriteFile(tmpFile, []byte("test cas content"), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	casHash, err := casEngine.MoveToCAS(tmpFile)
	if err != nil {
		t.Fatalf("CAS MoveToCAS failed: %v", err)
	}
	fileID := "file_test_lifecycle"
	_, err = dbEngine.SQL.Exec("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_starred, is_deleted) VALUES (?, 1, 'f1', 'test_doc.pdf', 'application/pdf', 100, ?, 0, 0)", fileID, casHash)
	if err != nil {
		t.Fatalf("DB insert failed: %v", err)
	}

	// 1. Soft-delete file (move to Trash)
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/files/"+fileID, nil)
	recDel := httptest.NewRecorder()
	cDel := e.NewContext(reqDel, recDel)
	cDel.SetPathValues(echo.PathValues{{Name: "id", Value: fileID}})

	if err := fileCtrl.DeleteFile(cDel); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	if recDel.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on soft-delete, got %d", recDel.Code)
	}

	// Verify file is in trash tab
	reqTrash := httptest.NewRequest(http.MethodGet, "/api/files?tab=trash", nil)
	recTrash := httptest.NewRecorder()
	cTrash := e.NewContext(reqTrash, recTrash)
	if err := fileCtrl.GetFiles(cTrash); err != nil {
		t.Fatalf("GetFiles tab=trash failed: %v", err)
	}
	var trashFiles []FileRecord
	json.Unmarshal(recTrash.Body.Bytes(), &trashFiles)
	if len(trashFiles) != 1 || trashFiles[0].ID != fileID {
		t.Fatalf("Expected file %s in trash tab, got %+v", fileID, trashFiles)
	}

	// 2. Restore file
	reqRest := httptest.NewRequest(http.MethodPost, "/api/files/"+fileID+"/restore", nil)
	recRest := httptest.NewRecorder()
	cRest := e.NewContext(reqRest, recRest)
	cRest.SetPathValues(echo.PathValues{{Name: "id", Value: fileID}})
	if err := fileCtrl.RestoreFile(cRest); err != nil {
		t.Fatalf("RestoreFile failed: %v", err)
	}
	if recRest.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on restore, got %d", recRest.Code)
	}

	// Verify file is back in storage tab
	reqStorage := httptest.NewRequest(http.MethodGet, "/api/files?tab=storage", nil)
	recStorage := httptest.NewRecorder()
	cStorage := e.NewContext(reqStorage, recStorage)
	if err := fileCtrl.GetFiles(cStorage); err != nil {
		t.Fatalf("GetFiles tab=storage failed: %v", err)
	}
	var storageFiles []FileRecord
	json.Unmarshal(recStorage.Body.Bytes(), &storageFiles)
	foundRestored := false
	for _, f := range storageFiles {
		if f.ID == fileID {
			foundRestored = true
			break
		}
	}
	if !foundRestored {
		t.Fatalf("Expected file %s in storage tab after restore", fileID)
	}

	// 3. Star file
	reqStar := httptest.NewRequest(http.MethodPost, "/api/files/"+fileID+"/star", nil)
	recStar := httptest.NewRecorder()
	cStar := e.NewContext(reqStar, recStar)
	cStar.SetPathValues(echo.PathValues{{Name: "id", Value: fileID}})
	if err := fileCtrl.StarFile(cStar); err != nil {
		t.Fatalf("StarFile failed: %v", err)
	}
	if recStar.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on star, got %d", recStar.Code)
	}

	// Verify file appears in starred tab
	reqStarred := httptest.NewRequest(http.MethodGet, "/api/files?tab=starred", nil)
	recStarred := httptest.NewRecorder()
	cStarred := e.NewContext(reqStarred, recStarred)
	if err := fileCtrl.GetFiles(cStarred); err != nil {
		t.Fatalf("GetFiles tab=starred failed: %v", err)
	}
	var starredFiles []FileRecord
	json.Unmarshal(recStarred.Body.Bytes(), &starredFiles)
	foundStarred := false
	for _, f := range starredFiles {
		if f.ID == fileID {
			foundStarred = true
			break
		}
	}
	if !foundStarred {
		t.Fatalf("Expected file %s in starred tab, got %+v", fileID, starredFiles)
	}

	// 4. Permanent delete
	reqPerm := httptest.NewRequest(http.MethodDelete, "/api/files/"+fileID+"?permanent=true", nil)
	recPerm := httptest.NewRecorder()
	cPerm := e.NewContext(reqPerm, recPerm)
	cPerm.SetPathValues(echo.PathValues{{Name: "id", Value: fileID}})
	if err := fileCtrl.DeleteFile(cPerm); err != nil {
		t.Fatalf("Permanent delete failed: %v", err)
	}
	if recPerm.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on permanent delete, got %d", recPerm.Code)
	}

	// Verify file is gone from DB
	var remainingCount int
	_ = dbEngine.SQL.QueryRow("SELECT COUNT(*) FROM files WHERE id = ?", fileID).Scan(&remainingCount)
	if remainingCount != 0 {
		t.Fatalf("Expected 0 rows in DB for file %s, got %d", fileID, remainingCount)
	}

	// Verify CAS object was removed since refcount dropped to 0
	if casEngine.Exists(casHash) {
		t.Fatalf("Expected CAS blob %s to be garbage collected", casHash)
	}
}

