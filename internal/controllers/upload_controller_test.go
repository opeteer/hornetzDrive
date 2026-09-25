package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"

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
