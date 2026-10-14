package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
	"ztatic-go-framework/realtime"
	"ztatic-go-framework/security/web"
)

func setupUploadTest(t *testing.T) (*echo.Echo, *UploadController) {
	e := echo.New()

	casEngine, err := storage.NewCASEngine(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	sessionMgr, err := upload.NewSessionManager(t.TempDir())
	if err != nil {
		t.Fatalf("Failed to init Session Manager: %v", err)
	}

	broker := realtime.NewMemoryBroker()

	ctrl := &UploadController{
		SessionMgr: sessionMgr,
		CAS:        casEngine,
		Broker:     broker,
	}

	return e, ctrl
}

func TestUploadController_InitSession(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	body := []byte(`{"filename":"test.txt","mime_type":"text/plain","size":100,"folder_id":"root"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := ctrl.InitSession(c); err != nil {
		t.Fatalf("InitSession error: %v", err)
	}

	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected HTTP 201, got %d", rec.Code)
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["session_id"] == "" {
		t.Fatalf("Expected session_id in response")
	}
}

func TestUploadController_ChunkUploadLifecycle(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	// 1. Create Session
	sess, err := ctrl.SessionMgr.CreateSession(1, "root", "cargo.dat", "application/octet-stream", 10)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 2. Upload Chunk
	chunk := []byte("0123456789")
	req := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader(chunk))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})
	c.Set("vault_key", crypto.DummyVK())

	if err := ctrl.UploadChunk(c); err != nil {
		t.Fatalf("UploadChunk error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on completion, got %d", rec.Code)
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["status"] != "completed" {
		t.Fatalf("Expected completed status, got %v", res["status"])
	}
	if res["cas_hash"] == "" {
		t.Fatalf("Expected cas_hash in response")
	}
}

func TestUploadController_ZeroByteFileUpload(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	// Create Session for 0-byte file
	sess, err := ctrl.SessionMgr.CreateSession(1, "root", "empty.txt", "text/plain", 0)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader([]byte{}))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})
	c.Set("vault_key", crypto.DummyVK())

	if err := ctrl.UploadChunk(c); err != nil {
		t.Fatalf("UploadChunk error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on 0-byte completion, got %d", rec.Code)
	}
}

func TestUploadController_WithCSRFProtection(t *testing.T) {
	e, ctrl := setupUploadTest(t)
	e.Use(web.HardenedCSRF())

	e.POST("/upload/init", ctrl.InitSession)

	// 1. Request without CSRF token should return HTTP 400 Bad Request
	body := []byte(`{"filename":"test.txt","mime_type":"text/plain","size":100,"folder_id":"root"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 without CSRF token, got %d", rec1.Code)
	}

	// 2. Request with _csrf cookie and matching X-CSRF-Token header should succeed (HTTP 201)
	csrfToken := "test-csrf-token-12345"
	req2 := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req2.Header.Set("X-CSRF-Token", csrfToken)
	req2.AddCookie(&http.Cookie{Name: "_csrf", Value: csrfToken})
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusCreated {
		t.Fatalf("Expected HTTP 201 with valid CSRF token, got %d (body: %s)", rec2.Code, rec2.Body.String())
	}
}

func TestUploadController_LargeFileMetadataOver2GB(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, plaintext_hash TEXT DEFAULT '', encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'test@hornetz.io', 'hash', 'salt', 'vk');
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f1', 1, NULL, 'Test Folder');
	`)
	if err != nil {
		t.Fatalf("DB setup failed: %v", err)
	}

	ctrl.DB = dbEngine

	// 4,064,980,992 bytes (~4.06 GB, > 2^31 - 1 = 2,147,483,647)
	largeFileSize := int64(4064980992)
	sess, err := ctrl.SessionMgr.CreateSession(1, "f1", "ultramarine-plasma-44-live-anaconda-x86_64.iso", "application/x-iso9660-image", largeFileSize)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Fast-forward UploadedSize to largeFileSize to simulate completing byte transmission
	sess.UploadedSize = largeFileSize

	req := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader([]byte{}))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})
	c.Set("vault_key", crypto.DummyVK())

	if err := ctrl.UploadChunk(c); err != nil {
		t.Fatalf("UploadChunk error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on completion, got %d, body: %s", rec.Code, rec.Body.String())
	}

	var rowSize int64
	var rowName string
	err = dbEngine.SQL.QueryRow("SELECT name, size FROM files WHERE size > 2147483647").Scan(&rowName, &rowSize)
	if err != nil {
		t.Fatalf("Failed to query inserted large file: %v", err)
	}
	if rowSize != largeFileSize {
		t.Fatalf("Expected size %d, got %d", largeFileSize, rowSize)
	}
	if rowName != "ultramarine-plasma-44-live-anaconda-x86_64.iso" {
		t.Fatalf("Expected filename 'ultramarine-plasma-44-live-anaconda-x86_64.iso', got %s", rowName)
	}
}

func TestUploadController_ZeroSecondDedup_InsertsFileRecord(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, plaintext_hash TEXT DEFAULT '', encrypted_metadata BLOB, is_starred BOOLEAN DEFAULT 0, is_deleted BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'test@hornetz.io', 'hash', 'salt', 'vk');
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('root', 1, NULL, 'Root');
	`)
	if err != nil {
		t.Fatalf("DB setup failed: %v", err)
	}
	ctrl.DB = dbEngine

	// Create an existing file in CAS
	existingHash := "d41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcdef"
	casFilePath := ctrl.CAS.Path(existingHash)
	_ = os.MkdirAll(filepath.Dir(casFilePath), 0700)
	_ = os.WriteFile(casFilePath, []byte("dedup target payload"), 0644)

	// User attempts to upload with matching cas_hash and valid proof of ownership
	proof := ctrl.GenerateProof(existingHash, "dedup_doc.pdf", 1234)
	body := []byte(`{"filename":"dedup_doc.pdf","mime_type":"application/pdf","size":1234,"folder_id":"root","cas_hash":"` + existingHash + `","proof":"` + proof + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := ctrl.InitSession(c); err != nil {
		t.Fatalf("InitSession error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on dedup match, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["status"] != "completed" {
		t.Fatalf("Expected status completed, got %v", res["status"])
	}

	// Verify that the file record is properly inserted into the files table
	var count int
	var fname string
	err = dbEngine.SQL.QueryRow("SELECT COUNT(*), COALESCE(MAX(name), '') FROM files WHERE cas_hash = ?", existingHash).Scan(&count, &fname)
	if err != nil {
		t.Fatalf("QueryRow failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("Expected 1 file row inserted on dedup match, got %d", count)
	}
	if fname != "dedup_doc.pdf" {
		t.Fatalf("Expected filename 'dedup_doc.pdf', got %s", fname)
	}
}

func TestUploadController_ZeroSecondDedup_WithoutProof_RequiresUpload(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, plaintext_hash TEXT DEFAULT '', encrypted_metadata BLOB, is_starred BOOLEAN DEFAULT 0, is_deleted BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'test@hornetz.io', 'hash', 'salt', 'vk');
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('root', 1, NULL, 'Root');
	`)
	if err != nil {
		t.Fatalf("DB setup failed: %v", err)
	}
	ctrl.DB = dbEngine

	// Create an existing file in CAS
	existingHash := "d41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcdef"
	casFilePath := ctrl.CAS.Path(existingHash)
	_ = os.MkdirAll(filepath.Dir(casFilePath), 0700)
	_ = os.WriteFile(casFilePath, []byte("dedup target payload"), 0644)

	// User attempts to upload with matching cas_hash but WITHOUT proof of ownership
	body := []byte(`{"filename":"dedup_doc.pdf","mime_type":"application/pdf","size":1234,"folder_id":"root","cas_hash":"` + existingHash + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := ctrl.InitSession(c); err != nil {
		t.Fatalf("InitSession error: %v", err)
	}

	// Should NOT immediately complete; should return 201 Created with a session_id for upload
	if rec.Code != http.StatusCreated {
		t.Fatalf("Expected HTTP 201 created session for upload, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["status"] == "completed" {
		t.Fatalf("Expected status not completed without proof, got %v", res["status"])
	}
	if res["session_id"] == "" || res["session_id"] == nil {
		t.Fatalf("Expected session_id to be returned for standard upload")
	}

	// Verify that NO file row was inserted
	var count int
	_ = dbEngine.SQL.QueryRow("SELECT COUNT(*) FROM files WHERE cas_hash = ?", existingHash).Scan(&count)
	if count != 0 {
		t.Fatalf("Expected 0 file rows inserted without proof, got %d", count)
	}
}

func TestUploadController_NegativeSize_Rejection(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	body := []byte(`{"filename":"malicious.txt","mime_type":"text/plain","size":-500,"folder_id":"root"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := ctrl.InitSession(c)
	if err == nil && rec.Code == http.StatusCreated {
		t.Fatalf("Expected InitSession to reject negative file size, but it succeeded")
	}
	if he, ok := err.(*echo.HTTPError); ok {
		if he.Code != http.StatusBadRequest {
			t.Fatalf("Expected HTTP 400, got %d", he.Code)
		}
	} else if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 Bad Request, got %d", rec.Code)
	}
}

func TestUploadController_FilenameSanitization(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	body := []byte(`{"filename":"../../../../etc/passwd","mime_type":"text/plain","size":100,"folder_id":"root"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := ctrl.InitSession(c); err != nil {
		t.Fatalf("InitSession error: %v", err)
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	sessID, ok := res["session_id"].(string)
	if !ok || sessID == "" {
		t.Fatalf("Expected session_id")
	}

	sess, found := ctrl.SessionMgr.GetSession(sessID)
	if !found {
		t.Fatalf("Session not found")
	}

	if sess.Filename != "passwd" {
		t.Fatalf("Expected sanitized filename 'passwd', got %q", sess.Filename)
	}
}

func TestUploadController_ChunkOverflow_Rejection(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	sess, err := ctrl.SessionMgr.CreateSession(1, "root", "tiny.txt", "text/plain", 10)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Send chunk that is larger than ExpectedSize (20 bytes > 10 bytes)
	chunk := []byte("01234567890123456789")
	req := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader(chunk))
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})
	c.Set("vault_key", crypto.DummyVK())

	err = ctrl.UploadChunk(c)
	if err == nil && rec.Code == http.StatusOK {
		t.Fatalf("Expected UploadChunk to reject chunk larger than expected size")
	}
	if he, ok := err.(*echo.HTTPError); ok {
		if he.Code != http.StatusBadRequest {
			t.Fatalf("Expected HTTP 400 for overflow chunk, got %d", he.Code)
		}
	} else if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 Bad Request, got %d", rec.Code)
	}
}

func TestUploadController_InvalidCasHashTraversal_Rejection(t *testing.T) {
	e, ctrl := setupUploadTest(t)
	e.POST("/upload/init", ctrl.InitSession)

	body := []byte(`{"filename":"test.txt","mime_type":"text/plain","size":100,"folder_id":"root","cas_hash":"../../etc/passwd"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 for path traversal cas_hash, got %d", rec.Code)
	}
}

func TestUploadController_NonexistentFolderID_Rejection(t *testing.T) {
	e, ctrl := setupUploadTest(t)
	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL);
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f1', 1, NULL, 'Root');
	`)
	ctrl.DB = dbEngine
	e.POST("/upload/init", ctrl.InitSession)

	// Attempt init with nonexistent folder
	body := []byte(`{"filename":"test.txt","mime_type":"text/plain","size":100,"folder_id":"nonexistent_folder_xyz"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 for nonexistent folder_id, got %d", rec.Code)
	}
}

func TestUploadController_AbortSession_CleansTempFile(t *testing.T) {
	e, ctrl := setupUploadTest(t)
	e.DELETE("/upload/:session_id", ctrl.AbortSession)

	sess, err := ctrl.SessionMgr.CreateSession(1, "f1", "abort_test.bin", "application/octet-stream", 1024)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Write some temp data
	_ = os.WriteFile(sess.TempFilePath, []byte("temporary data"), 0644)
	if _, err := os.Stat(sess.TempFilePath); os.IsNotExist(err) {
		t.Fatalf("Temp file does not exist before abort")
	}

	req := httptest.NewRequest(http.MethodDelete, "/upload/"+sess.ID, nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on AbortSession, got %d", rec.Code)
	}

	// Verify temp file was removed
	if _, err := os.Stat(sess.TempFilePath); !os.IsNotExist(err) {
		t.Fatalf("Temp file was not cleaned up after abort")
	}

	// Verify session is deleted
	if _, exists := ctrl.SessionMgr.GetSession(sess.ID); exists {
		t.Fatalf("Session was not removed from SessionMgr")
	}
}

func TestUploadController_GetStatus_CompletedSession(t *testing.T) {
	e, ctrl := setupUploadTest(t)
	e.GET("/upload/:session_id", ctrl.GetStatus)

	// Simulate completed session stored in completedSessions cache
	ctrl.completedSessions.Store("completed_sess_1", time.Now())

	req := httptest.NewRequest(http.MethodGet, "/upload/completed_sess_1", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 for completed session status, got %d", rec.Code)
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["status"] != "completed" {
		t.Fatalf("Expected status 'completed', got %v", res["status"])
	}
}

func TestUploadController_VaultUploadChunk_UnauthenticatedRejection(t *testing.T) {
	e, ctrl := setupUploadTest(t)
	// Apply VaultKeyMiddleware to test the fallback handling
	uploadGroup := e.Group("/upload", auth.VaultKeyMiddleware())
	uploadGroup.PUT("/:session_id", ctrl.UploadChunk)

	// Create a session for folder 'f2' (vault folder)
	sess, err := ctrl.SessionMgr.CreateSession(1, "f2", "secret_plan.kdbx", "application/octet-stream", 100)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Attempt chunk upload WITHOUT vault authentication cookie
	req := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader(make([]byte, 100)))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("BUG-SEC-42: Expected HTTP 401 Unauthorized for unauthenticated vault chunk upload, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadController_ProofOfOwnership_BackdoorRejected(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt BLOB NOT NULL, encrypted_vault_key BLOB NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, parent_id TEXT, name TEXT NOT NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, plaintext_hash TEXT DEFAULT '', encrypted_metadata BLOB, is_starred BOOLEAN DEFAULT 0, is_deleted BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'test@hornetz.io', 'hash', 'salt', 'vk');
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('root', 1, NULL, 'Root');
	`)
	if err != nil {
		t.Fatalf("DB setup failed: %v", err)
	}
	ctrl.DB = dbEngine

	existingHash := "d41d8cd98f00b204e9800998ecf8427e0123456789abcdef0123456789abcdef"
	casFilePath := ctrl.CAS.Path(existingHash)
	_ = os.MkdirAll(filepath.Dir(casFilePath), 0700)
	_ = os.WriteFile(casFilePath, []byte("dedup target payload"), 0644)

	// Attacker attempts to upload with matching cas_hash and backdoor proof "pow_verified"
	body := []byte(`{"filename":"stolen.pdf","mime_type":"application/pdf","size":9999,"folder_id":"root","cas_hash":"` + existingHash + `","proof":"pow_verified"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := ctrl.InitSession(c); err != nil {
		t.Fatalf("InitSession error: %v", err)
	}

	// Must NOT return 200 with completed; should return 201 Created standard session
	if rec.Code != http.StatusCreated {
		t.Fatalf("BUG-SEC-45: Expected HTTP 201 created (dedup rejected), got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadController_AbortSession_VaultAuthentication(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	sess, err := ctrl.SessionMgr.CreateSession(1, "f2", "vault_file.enc", "application/octet-stream", 1024)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Unauthenticated abort request on vault session
	req := httptest.NewRequest(http.MethodDelete, "/upload/"+sess.ID, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})

	errAbort := ctrl.AbortSession(c)
	if errAbort == nil {
		t.Fatalf("BUG-SEC-43: Expected 401 Unauthorized for unauthenticated vault session abort, got success")
	}
	he, ok := errAbort.(*echo.HTTPError)
	if !ok || he.Code != http.StatusUnauthorized {
		t.Fatalf("BUG-SEC-43: Expected HTTP 401 Unauthorized, got: %v", errAbort)
	}

	// Verify session still exists
	_, exists := ctrl.SessionMgr.GetSession(sess.ID)
	if !exists {
		t.Fatalf("BUG-SEC-43: Session was unexpectedly deleted by unauthenticated caller")
	}
}

func TestUploadController_GetStatus_VaultAuthentication(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	sess, err := ctrl.SessionMgr.CreateSession(1, "f2", "vault_secret.pdf", "application/pdf", 5000)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}

	// Unauthenticated get status request on vault session
	req := httptest.NewRequest(http.MethodGet, "/upload/"+sess.ID, nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})

	errStatus := ctrl.GetStatus(c)
	if errStatus == nil {
		t.Fatalf("BUG-SEC-44: Expected 401 Unauthorized for unauthenticated vault get status, got success")
	}
	he, ok := errStatus.(*echo.HTTPError)
	if !ok || he.Code != http.StatusUnauthorized {
		t.Fatalf("BUG-SEC-44: Expected HTTP 401 Unauthorized, got: %v", errStatus)
	}
}

func TestUploadController_ZeroByteDirectory_Rejected(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	// Attempt to upload a 0-byte directory dummy object (name="ensiklopedia", size=0, generic binary mime)
	bodyDir := []byte(`{"filename":"ensiklopedia","mime_type":"application/octet-stream","size":0,"folder_id":"root"}`)
	reqDir := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(bodyDir))
	reqDir.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recDir := httptest.NewRecorder()
	cDir := e.NewContext(reqDir, recDir)

	errDir := ctrl.InitSession(cDir)
	if errDir == nil {
		t.Fatalf("Expected 400 Bad Request for 0-byte directory upload, but got nil")
	}
	heDir, ok := errDir.(*echo.HTTPError)
	if !ok || heDir.Code != http.StatusBadRequest {
		t.Fatalf("Expected HTTP 400 Bad Request, got: %v", errDir)
	}

	// Legitimate 0-byte file with file extension (e.g. empty.txt) should be allowed
	bodyFile := []byte(`{"filename":"empty.txt","mime_type":"text/plain","size":0,"folder_id":"root"}`)
	reqFile := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(bodyFile))
	reqFile.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recFile := httptest.NewRecorder()
	cFile := e.NewContext(reqFile, recFile)

	errFile := ctrl.InitSession(cFile)
	if errFile != nil {
		t.Fatalf("Expected success for legitimate empty file with extension, got error: %v", errFile)
	}
	if recFile.Code != http.StatusCreated {
		t.Fatalf("Expected HTTP 201 Created for empty.txt, got %d: %s", recFile.Code, recFile.Body.String())
	}
}

func TestUploadController_ResumeHalfUploadedSession(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	// 1. First init session for a 20-byte file
	body1 := []byte(`{"filename":"resume_me.bin","mime_type":"application/octet-stream","size":20,"folder_id":"root"}`)
	req1 := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body1))
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec1 := httptest.NewRecorder()
	c1 := e.NewContext(req1, rec1)

	if err := ctrl.InitSession(c1); err != nil {
		t.Fatalf("InitSession 1 error: %v", err)
	}
	if rec1.Code != http.StatusCreated {
		t.Fatalf("Expected 201 Created, got %d", rec1.Code)
	}
	var res1 map[string]interface{}
	json.Unmarshal(rec1.Body.Bytes(), &res1)
	sessID := res1["session_id"].(string)

	// 2. Upload chunk of 10 bytes (half-uploaded) with Content-Range
	chunk1 := []byte("0123456789")
	reqChunk1 := httptest.NewRequest(http.MethodPut, "/upload/"+sessID, bytes.NewReader(chunk1))
	reqChunk1.Header.Set("Content-Range", "bytes 0-9/20")
	recChunk1 := httptest.NewRecorder()
	cChunk1 := e.NewContext(reqChunk1, recChunk1)
	cChunk1.SetPathValues(echo.PathValues{{Name: "session_id", Value: sessID}})

	if err := ctrl.UploadChunk(cChunk1); err != nil {
		t.Fatalf("UploadChunk 1 error: %v", err)
	}
	if recChunk1.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for chunk 1, got %d", recChunk1.Code)
	}

	// 3. User attempts to upload the same file again (e.g. after network drop / reconnect)
	req2 := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body1))
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec2 := httptest.NewRecorder()
	c2 := e.NewContext(req2, rec2)

	if err := ctrl.InitSession(c2); err != nil {
		t.Fatalf("InitSession 2 error: %v", err)
	}

	// Should return HTTP 200 with resumed=true and uploaded=10
	if rec2.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 for resuming half-uploaded session, got %d: %s", rec2.Code, rec2.Body.String())
	}
	var res2 map[string]interface{}
	json.Unmarshal(rec2.Body.Bytes(), &res2)
	if res2["resumed"] != true {
		t.Fatalf("Expected resumed to be true, got %v", res2["resumed"])
	}
	if int64(res2["uploaded"].(float64)) != 10 {
		t.Fatalf("Expected uploaded to be 10, got %v", res2["uploaded"])
	}
	if res2["session_id"] != sessID {
		t.Fatalf("Expected matching session_id %s, got %v", sessID, res2["session_id"])
	}

	// 4. Client completes the remaining 10 bytes starting from byte 10
	chunk2 := []byte("ABCDEFGHIJ")
	reqChunk2 := httptest.NewRequest(http.MethodPut, "/upload/"+sessID, bytes.NewReader(chunk2))
	reqChunk2.Header.Set("Content-Range", "bytes 10-19/20")
	recChunk2 := httptest.NewRecorder()
	cChunk2 := e.NewContext(reqChunk2, recChunk2)
	cChunk2.SetPathValues(echo.PathValues{{Name: "session_id", Value: sessID}})

	if err := ctrl.UploadChunk(cChunk2); err != nil {
		t.Fatalf("UploadChunk 2 error: %v", err)
	}
	if recChunk2.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK on completion, got %d: %s", recChunk2.Code, recChunk2.Body.String())
	}
	var resChunk2 map[string]interface{}
	json.Unmarshal(recChunk2.Body.Bytes(), &resChunk2)
	if resChunk2["status"] != "completed" {
		t.Fatalf("Expected completed status, got %v", resChunk2["status"])
	}
}

func TestUploadController_DuplicateChunkProtection(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	sess, err := ctrl.SessionMgr.CreateSession(1, "root", "dup_test.bin", "application/octet-stream", 30)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 1. Send first chunk 0-9
	chunk := []byte("0123456789")
	req1 := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader(chunk))
	req1.Header.Set("Content-Range", "bytes 0-9/30")
	rec1 := httptest.NewRecorder()
	c1 := e.NewContext(req1, rec1)
	c1.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})

	if err := ctrl.UploadChunk(c1); err != nil {
		t.Fatalf("UploadChunk 1 error: %v", err)
	}
	if rec1.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rec1.Code)
	}

	// Get temp file size after chunk 1
	info1, err := os.Stat(sess.TempFilePath)
	if err != nil {
		t.Fatalf("Stat temp file failed: %v", err)
	}
	fileSizeAfterChunk1 := info1.Size()

	// 2. Re-send exact same chunk 0-9 (simulating network retry where client missed response)
	reqDup := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader(chunk))
	reqDup.Header.Set("Content-Range", "bytes 0-9/30")
	recDup := httptest.NewRecorder()
	cDup := e.NewContext(reqDup, recDup)
	cDup.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})

	if err := ctrl.UploadChunk(cDup); err != nil {
		t.Fatalf("UploadChunk duplicate error: %v", err)
	}
	if recDup.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for duplicate chunk, got %d", recDup.Code)
	}

	// Verify temp file size did NOT grow (duplicate bytes avoided!)
	info2, _ := os.Stat(sess.TempFilePath)
	if info2.Size() != fileSizeAfterChunk1 {
		t.Fatalf("Duplicate chunk was appended to file! Expected size %d, got %d", fileSizeAfterChunk1, info2.Size())
	}
	if sess.UploadedSize != 10 {
		t.Fatalf("Expected UploadedSize to remain 10, got %d", sess.UploadedSize)
	}
}

func TestUploadController_ContentRangeMismatch(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	sess, err := ctrl.SessionMgr.CreateSession(1, "root", "mismatch.bin", "application/octet-stream", 50)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Send chunk starting at byte 20 when server is at byte 0
	chunk := []byte("0123456789")
	req := httptest.NewRequest(http.MethodPut, "/upload/"+sess.ID, bytes.NewReader(chunk))
	req.Header.Set("Content-Range", "bytes 20-29/50")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.SetPathValues(echo.PathValues{{Name: "session_id", Value: sess.ID}})

	errChunk := ctrl.UploadChunk(c)
	if errChunk != nil {
		// Could be an error or HTTP status
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("Expected HTTP 409 Conflict for offset mismatch, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestUploadController_AlreadyCompletedFile_InstantCompleted(t *testing.T) {
	e, ctrl := setupUploadTest(t)

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, salt BLOB, encrypted_vault_key BLOB);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER, parent_id TEXT, name TEXT);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER, folder_id TEXT, name TEXT, mime_type TEXT, size BIGINT, cas_hash TEXT, is_deleted BOOLEAN DEFAULT FALSE);
		INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted) VALUES 
			('done_file_1', 1, 'f1', 'already_done.pdf', 'application/pdf', 1048576, 'dummy_cas_done', FALSE);
	`)
	ctrl.DB = dbEngine

	body := []byte(`{"filename":"already_done.pdf","mime_type":"application/pdf","size":1048576,"folder_id":"f1"}`)
	req := httptest.NewRequest(http.MethodPost, "/upload/init", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := ctrl.InitSession(c); err != nil {
		t.Fatalf("InitSession error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 OK for already completed file, got %d: %s", rec.Code, rec.Body.String())
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["status"] != "completed" {
		t.Fatalf("Expected status 'completed', got %v", res["status"])
	}
	if res["file_id"] != "done_file_1" {
		t.Fatalf("Expected file_id 'done_file_1', got %v", res["file_id"])
	}
}








