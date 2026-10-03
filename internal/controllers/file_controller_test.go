package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
	_ "github.com/mattn/go-sqlite3"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
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

	// 2. Test vault tab filtering: unauthenticated tab=vault must return 401 Unauthorized (BUG-SEC-18)
	reqVaultUnauth := httptest.NewRequest(http.MethodGet, "/api/files?tab=vault", nil)
	recVaultUnauth := httptest.NewRecorder()
	cVaultUnauth := e.NewContext(reqVaultUnauth, recVaultUnauth)
	errUnauth := fileCtrl.GetFiles(cVaultUnauth)
	if errUnauth == nil {
		t.Fatalf("Expected 401 Unauthorized for unauthenticated vault access")
	}

	// Authenticated access with valid vault session
	auth.GlobalSessionStore.SetKey("test_vault_sess", crypto.DummyVK())
	reqVault := httptest.NewRequest(http.MethodGet, "/api/files?tab=vault", nil)
	reqVault.AddCookie(&http.Cookie{Name: "swarm_session", Value: "test_vault_sess"})
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
	// Unauthenticated stats should exclude vault files (seed has 3 public, 1 vault)
	if stats.FileCount != 3 {
		t.Fatalf("Expected 3 files when unauthenticated, got %d", stats.FileCount)
	}
	if stats.QuotaFormatted != "2 TB" {
		t.Fatalf("Expected quota_formatted '2 TB', got %s", stats.QuotaFormatted)
	}
	if stats.PercentUsed <= 0 || stats.PercentUsed > 100 {
		t.Fatalf("Invalid percent_used: %f", stats.PercentUsed)
	}

	// Authenticated request with session key should include vault files
	sessionID := "test-stats-session"
	auth.GlobalSessionStore.SetKey(sessionID, crypto.DummyVK())
	authReq := httptest.NewRequest(http.MethodGet, "/api/storage/stats", nil)
	authReq.AddCookie(&http.Cookie{Name: "swarm_session", Value: sessionID})
	authRec := httptest.NewRecorder()
	authC := e.NewContext(authReq, authRec)
	if err := fileCtrl.GetStorageStats(authC); err != nil {
		t.Fatalf("GetStorageStats error: %v", err)
	}
	var authStats StorageStats
	if err := json.Unmarshal(authRec.Body.Bytes(), &authStats); err != nil {
		t.Fatalf("Failed to unmarshal storage stats: %v", err)
	}
	if authStats.FileCount != 4 {
		t.Fatalf("Expected 4 files when authenticated, got %d", authStats.FileCount)
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
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, is_starred BOOLEAN DEFAULT FALSE, is_deleted BOOLEAN DEFAULT FALSE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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

	// 3. Test BUG-SEC-41: Download standard file while user is logged in to vault with custom MEK
	vaultKey := []byte("vaultsecretkey1234567890abcdef12")
	auth.GlobalSessionStore.SetKey("sess_contam_test", vaultKey)
	reqLoggedIn := httptest.NewRequest(http.MethodGet, "/api/files/real_cas_1/download", nil)
	reqLoggedIn.AddCookie(&http.Cookie{Name: "swarm_session", Value: "sess_contam_test"})
	recLoggedIn := httptest.NewRecorder()
	e.ServeHTTP(recLoggedIn, reqLoggedIn)

	if recLoggedIn.Code != http.StatusOK {
		t.Fatalf("BUG-SEC-41 Regression: Logged-in vault user failed to download standard file! Status: %d, body: %s", recLoggedIn.Code, recLoggedIn.Body.String())
	}
	if !bytes.Equal(recLoggedIn.Body.Bytes(), secretData) {
		t.Fatalf("BUG-SEC-41: Decrypted data mismatch when downloading standard file while logged in to vault")
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

func TestFileController_CreateFolder(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f1', 1, NULL, 'Dokumen Utama');
	`)

	fileCtrl := &FileController{DB: dbEngine}
	e.POST("/api/folders", fileCtrl.CreateFolder)

	// 1. Success create folder
	body := `{"name": "Proyek Alpha", "parent_id": "f1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/folders", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected HTTP 201, got %d: %s", rec.Code, rec.Body.String())
	}

	// 2. Empty name should return 400
	bodyEmpty := `{"name": "   ", "parent_id": "f1"}`
	reqEmpty := httptest.NewRequest(http.MethodPost, "/api/folders", strings.NewReader(bodyEmpty))
	reqEmpty.Header.Set("Content-Type", "application/json")
	recEmpty := httptest.NewRecorder()
	e.ServeHTTP(recEmpty, reqEmpty)

	if recEmpty.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 for empty folder name, got %d", recEmpty.Code)
	}

	// 3. Nonexistent parent folder should return 400
	bodyBadParent := `{"name": "Subfolder", "parent_id": "nonexistent_f"}`
	reqBadParent := httptest.NewRequest(http.MethodPost, "/api/folders", strings.NewReader(bodyBadParent))
	reqBadParent.Header.Set("Content-Type", "application/json")
	recBadParent := httptest.NewRecorder()
	e.ServeHTTP(recBadParent, reqBadParent)

	if recBadParent.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 for bad parent_id, got %d", recBadParent.Code)
	}
}

func TestFileController_VaultDownload_Authentication(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, is_starred BOOLEAN DEFAULT FALSE, is_deleted BOOLEAN DEFAULT FALSE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES ('vault_file_1', 1, 'f2', 'secret.kdbx', 'application/octet-stream', 100, 'somehash');
	`)

	fileCtrl := &FileController{DB: dbEngine}
	e.GET("/api/files/:id/download", fileCtrl.DownloadFile)

	// 1. Without session cookie -> 401
	reqNoAuth := httptest.NewRequest(http.MethodGet, "/api/files/vault_file_1/download", nil)
	recNoAuth := httptest.NewRecorder()
	e.ServeHTTP(recNoAuth, reqNoAuth)

	if recNoAuth.Code != http.StatusUnauthorized {
		t.Fatalf("Expected HTTP 401 for unauthenticated vault download, got %d", recNoAuth.Code)
	}

	// 2. With valid session cookie -> 200 (mock fallback)
	auth.GlobalSessionStore.SetKey("sess_test_vault", []byte("32byteslongsecretkeyforaesgcm123"))
	defer auth.GlobalSessionStore.DeleteKey("sess_test_vault")

	reqAuth := httptest.NewRequest(http.MethodGet, "/api/files/vault_file_1/download", nil)
	reqAuth.AddCookie(&http.Cookie{Name: "swarm_session", Value: "sess_test_vault"})
	recAuth := httptest.NewRecorder()
	e.ServeHTTP(recAuth, reqAuth)

	if recAuth.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 with valid session, got %d", recAuth.Code)
	}
}

func TestFileController_NotFoundOnNonexistent(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, is_starred BOOLEAN DEFAULT FALSE, is_deleted BOOLEAN DEFAULT FALSE);
	`)

	fileCtrl := &FileController{DB: dbEngine}
	e.DELETE("/api/files/:id", fileCtrl.DeleteFile)
	e.POST("/api/files/:id/restore", fileCtrl.RestoreFile)
	e.POST("/api/files/:id/star", fileCtrl.StarFile)

	// Delete nonexistent
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/files/no_such_file", nil)
	recDel := httptest.NewRecorder()
	e.ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusNotFound {
		t.Fatalf("Expected HTTP 404 for DeleteFile nonexistent, got %d", recDel.Code)
	}

	// Restore nonexistent
	reqRest := httptest.NewRequest(http.MethodPost, "/api/files/no_such_file/restore", nil)
	recRest := httptest.NewRecorder()
	e.ServeHTTP(recRest, reqRest)
	if recRest.Code != http.StatusNotFound {
		t.Fatalf("Expected HTTP 404 for RestoreFile nonexistent, got %d", recRest.Code)
	}

	// Star nonexistent
	reqStar := httptest.NewRequest(http.MethodPost, "/api/files/no_such_file/star", nil)
	recStar := httptest.NewRecorder()
	e.ServeHTTP(recStar, reqStar)
	if recStar.Code != http.StatusNotFound {
		t.Fatalf("Expected HTTP 404 for StarFile nonexistent, got %d", recStar.Code)
	}
}

func TestFileController_DeleteFolder_And_RenameFolder(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, is_deleted BOOLEAN DEFAULT FALSE);
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_test', 1, NULL, 'Original Folder');
		INSERT INTO files (id, owner_id, folder_id, name, is_deleted) VALUES ('file_inside', 1, 'f_test', 'test.txt', FALSE);
	`)

	fileCtrl := &FileController{DB: dbEngine}
	e.DELETE("/api/folders/:id", fileCtrl.DeleteFolder)
	e.PATCH("/api/folders/:id", fileCtrl.RenameFolder)

	// 1. Rename folder
	renameBody := `{"name": "Renamed Folder"}`
	reqRename := httptest.NewRequest(http.MethodPatch, "/api/folders/f_test", strings.NewReader(renameBody))
	reqRename.Header.Set("Content-Type", "application/json")
	recRename := httptest.NewRecorder()
	e.ServeHTTP(recRename, reqRename)

	if recRename.Code != http.StatusOK {
		t.Fatalf("RenameFolder returned %d: %s", recRename.Code, recRename.Body.String())
	}

	var folderName string
	_ = dbEngine.SQL.QueryRow("SELECT name FROM folders WHERE id = 'f_test'").Scan(&folderName)
	if folderName != "Renamed Folder" {
		t.Fatalf("Expected folder name 'Renamed Folder', got %s", folderName)
	}

	// 2. Delete folder
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/folders/f_test", nil)
	recDel := httptest.NewRecorder()
	e.ServeHTTP(recDel, reqDel)

	if recDel.Code != http.StatusOK {
		t.Fatalf("DeleteFolder returned %d: %s", recDel.Code, recDel.Body.String())
	}

	var count int
	_ = dbEngine.SQL.QueryRow("SELECT COUNT(*) FROM folders WHERE id = 'f_test'").Scan(&count)
	if count != 0 {
		t.Fatalf("Expected folder to be deleted from DB")
	}

	// Check that file was soft deleted
	var isDeleted bool
	_ = dbEngine.SQL.QueryRow("SELECT is_deleted FROM files WHERE id = 'file_inside'").Scan(&isDeleted)
	if !isDeleted {
		t.Fatalf("Expected file inside deleted folder to be marked deleted")
	}
}

func TestFileController_EmptyTrash(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, cas_hash TEXT NOT NULL, is_deleted BOOLEAN DEFAULT FALSE);
		INSERT INTO files (id, owner_id, folder_id, name, cas_hash, is_deleted) VALUES 
			('f_active', 1, 'f1', 'active.txt', 'hash1', FALSE),
			('f_trash1', 1, 'f1', 'del1.txt', 'hash2', TRUE),
			('f_trash2', 1, 'f1', 'del2.txt', 'hash3', TRUE);
	`)

	fileCtrl := &FileController{DB: dbEngine}
	e.DELETE("/api/files/trash/empty", fileCtrl.EmptyTrash)

	req := httptest.NewRequest(http.MethodDelete, "/api/files/trash/empty", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("EmptyTrash returned %d: %s", rec.Code, rec.Body.String())
	}

	var totalFiles, trashFiles int
	_ = dbEngine.SQL.QueryRow("SELECT COUNT(*) FROM files").Scan(&totalFiles)
	_ = dbEngine.SQL.QueryRow("SELECT COUNT(*) FROM files WHERE is_deleted = TRUE").Scan(&trashFiles)

	if totalFiles != 1 || trashFiles != 0 {
		t.Fatalf("Expected only 1 active file left and 0 trash files, got %d total, %d trash", totalFiles, trashFiles)
	}
}

func TestFileController_RangeRequest_And_DeletedDownload(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, is_deleted BOOLEAN DEFAULT FALSE);
		INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted) VALUES 
			('mock_active', 1, 'f1', 'test.txt', 'text/plain', 50, 'hash1', FALSE),
			('mock_trashed', 1, 'f1', 'trash.txt', 'text/plain', 50, 'hash2', TRUE);
	`)

	fileCtrl := &FileController{DB: dbEngine}
	e.GET("/api/files/:id/download", fileCtrl.DownloadFile)

	// 1. Download trashed file -> 404 (BUG-SEC-21)
	reqTrash := httptest.NewRequest(http.MethodGet, "/api/files/mock_trashed/download", nil)
	recTrash := httptest.NewRecorder()
	e.ServeHTTP(recTrash, reqTrash)
	if recTrash.Code != http.StatusNotFound {
		t.Fatalf("Expected HTTP 404 downloading trashed file, got %d", recTrash.Code)
	}

	// 2. HTTP Range request bytes=0-10 -> 206 Partial Content (BUG-SYS-20)
	reqRange := httptest.NewRequest(http.MethodGet, "/api/files/mock_active/download", nil)
	reqRange.Header.Set("Range", "bytes=0-10")
	recRange := httptest.NewRecorder()
	e.ServeHTTP(recRange, reqRange)

	if recRange.Code != http.StatusPartialContent {
		t.Fatalf("Expected HTTP 206 Partial Content for range request, got %d", recRange.Code)
	}
	if recRange.Header().Get("Accept-Ranges") != "bytes" {
		t.Errorf("Expected Accept-Ranges: bytes, got %q", recRange.Header().Get("Accept-Ranges"))
	}
	if !strings.HasPrefix(recRange.Header().Get("Content-Range"), "bytes 0-10/") {
		t.Errorf("Unexpected Content-Range: %q", recRange.Header().Get("Content-Range"))
	}
	if len(recRange.Body.Bytes()) != 11 {
		t.Errorf("Expected 11 bytes returned for bytes=0-10, got %d", len(recRange.Body.Bytes()))
	}
}

func TestFileController_SortAndPagination(t *testing.T) {
	e := echo.New()
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, is_starred BOOLEAN DEFAULT FALSE, is_deleted BOOLEAN DEFAULT FALSE, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'u', 'p', 's', 'k');
		INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_starred, is_deleted, created_at) VALUES 
			('f1', 1, 'folder1', 'alpha.txt', 'text/plain', 100, 'h1', FALSE, FALSE, '2026-01-01 10:00:00'),
			('f2', 1, 'folder1', 'beta.txt', 'text/plain', 500, 'h2', FALSE, FALSE, '2026-01-02 10:00:00'),
			('f3', 1, 'folder1', 'gamma.txt', 'text/plain', 300, 'h3', FALSE, FALSE, '2026-01-03 10:00:00');
	`)

	fileCtrl := &FileController{DB: dbEngine}
	e.GET("/api/files", fileCtrl.GetFiles)

	// Sort by name ASC
	reqSort := httptest.NewRequest(http.MethodGet, "/api/files?sort_by=name&order=asc", nil)
	recSort := httptest.NewRecorder()
	e.ServeHTTP(recSort, reqSort)
	var sortedFiles []FileRecord
	json.Unmarshal(recSort.Body.Bytes(), &sortedFiles)
	if len(sortedFiles) != 3 || sortedFiles[0].Name != "alpha.txt" || sortedFiles[2].Name != "gamma.txt" {
		t.Fatalf("Unexpected sort by name asc result: %+v", sortedFiles)
	}

	// Pagination limit=1&offset=1
	reqPage := httptest.NewRequest(http.MethodGet, "/api/files?sort_by=name&order=asc&limit=1&offset=1", nil)
	recPage := httptest.NewRecorder()
	e.ServeHTTP(recPage, reqPage)
	var pagedFiles []FileRecord
	json.Unmarshal(recPage.Body.Bytes(), &pagedFiles)
	if len(pagedFiles) != 1 || pagedFiles[0].Name != "beta.txt" {
		t.Fatalf("Unexpected paged result: %+v", pagedFiles)
	}
}



