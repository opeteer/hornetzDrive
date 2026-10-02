package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/data"
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
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER NOT NULL, folder_id TEXT, name TEXT NOT NULL, mime_type TEXT NOT NULL, size BIGINT NOT NULL, cas_hash TEXT NOT NULL, encrypted_metadata BLOB, is_starred BOOLEAN DEFAULT 0, is_deleted BOOLEAN DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
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
	_ = os.WriteFile(casFilePath, []byte("dedup target payload"), 0644)

	// User attempts to upload with matching cas_hash
	body := []byte(`{"filename":"dedup_doc.pdf","mime_type":"application/pdf","size":1234,"folder_id":"root","cas_hash":"` + existingHash + `"}`)
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


