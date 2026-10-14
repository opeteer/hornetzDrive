package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	_ "github.com/mattn/go-sqlite3"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/download"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/realtime"
)

func setupDownloadControllerTest(t *testing.T) (*echo.Echo, *DownloadController, *httptest.Server) {
	e := echo.New()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to init memory DB: %v", err)
	}

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password_hash TEXT, salt BLOB, encrypted_vault_key BLOB);
		CREATE TABLE folders (id TEXT PRIMARY KEY, owner_id INTEGER, parent_id TEXT, name TEXT);
		CREATE TABLE files (id TEXT PRIMARY KEY, owner_id INTEGER, folder_id TEXT, name TEXT, mime_type TEXT, size BIGINT, cas_hash TEXT, plaintext_hash TEXT, encrypted_metadata BLOB, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP);
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f1', 1, NULL, 'Documents');
		INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f2', 1, NULL, 'Vault');
	`)
	if err != nil {
		t.Fatalf("Schema init failed: %v", err)
	}

	casEngine, err := storage.NewCASEngine(t.TempDir())
	if err != nil {
		t.Fatalf("CAS init failed: %v", err)
	}

	broker := realtime.NewMemoryBroker()
	mgr, err := download.NewDownloadManager(casEngine, dbEngine, broker, t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewDownloadManager failed: %v", err)
	}

	ctrl := &DownloadController{
		Manager: mgr,
		DB:      dbEngine,
		CAS:     casEngine,
	}

	download.AllowPrivateNetworks = true
	e.POST("/api/downloads", ctrl.StartDownload)
	e.POST("/api/downloads/batch", ctrl.StartBatchDownload)
	e.GET("/api/downloads/:id", ctrl.GetDownloadStatus)
	e.DELETE("/api/downloads/:id", ctrl.CancelDownload)
	e.POST("/api/downloads/parse", ctrl.ParseLink)

	// Mock HTTP file server for downloads
	fileServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Disposition", `attachment; filename="remote_file.bin"`)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Sample remote downloaded content!"))
	}))

	return e, ctrl, fileServer
}

func TestDownloadController_StartDownload_Direct(t *testing.T) {
	e, ctrl, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	payload := map[string]string{
		"url":       fs.URL + "/remote_file.bin",
		"folder_id": "f1",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/downloads", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("Expected HTTP 202, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var res download.DownloadTask
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("Unmarshal response failed: %v", err)
	}

	if res.ID == "" || res.Type != download.DownloadTypeDirect {
		t.Errorf("Unexpected task response: %+v", res)
	}

	// Wait for completion
	deadline := time.Now().Add(3 * time.Second)
	var finalTask *download.DownloadTask
	for time.Now().Before(deadline) {
		tSnap, found := ctrl.Manager.GetTask(res.ID)
		if found && tSnap.Status == download.StatusCompleted {
			finalTask = tSnap
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if finalTask == nil || finalTask.Status != download.StatusCompleted {
		t.Fatalf("Direct download task did not complete")
	}

	// Verify status endpoint
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/downloads/"+res.ID, nil)
	recStatus := httptest.NewRecorder()
	e.ServeHTTP(recStatus, reqStatus)

	if recStatus.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for status, got %d", recStatus.Code)
	}
}

func TestDownloadController_StartDownload_Magnet(t *testing.T) {
	e, ctrl, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	magURI := "magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=sample.iso&ws=" + fs.URL + "/sample.iso"
	payload := map[string]string{
		"url":       magURI,
		"folder_id": "f1",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/downloads", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("Expected HTTP 202, got %d", rec.Code)
	}

	var res download.DownloadTask
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.ID != "" {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			tSnap, found := ctrl.Manager.GetTask(res.ID)
			if found && (tSnap.Status == download.StatusCompleted || tSnap.Status == download.StatusFailed || tSnap.Status == download.StatusCancelled) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestDownloadController_StartDownload_InvalidLink(t *testing.T) {
	e, _, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	payload := map[string]string{
		"url": "not-a-valid-link",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/downloads", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("Expected HTTP 400 Bad Request, got %d", rec.Code)
	}
}

func TestDownloadController_VaultProtection(t *testing.T) {
	e, ctrl, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	payload := map[string]string{
		"url":       fs.URL + "/data.bin",
		"folder_id": "f2", // Vault folder
	}
	body, _ := json.Marshal(payload)

	// 1. Without vault unlock -> should return HTTP 401 Unauthorized
	req1 := httptest.NewRequest(http.MethodPost, "/api/downloads", bytes.NewReader(body))
	req1.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for locked vault download, got %d", rec1.Code)
	}

	// 2. With vault unlocked in session store -> should succeed
	auth.GlobalSessionStore.SetKey("test_session_123", crypto.DummyVK())
	defer auth.GlobalSessionStore.DeleteKey("test_session_123")

	req2 := httptest.NewRequest(http.MethodPost, "/api/downloads", bytes.NewReader(body))
	req2.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	req2.AddCookie(&http.Cookie{Name: "swarm_session", Value: "test_session_123"})
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusAccepted {
		t.Errorf("Expected 202 Accepted, got %d", rec2.Code)
	}

	var res download.DownloadTask
	json.Unmarshal(rec2.Body.Bytes(), &res)
	if res.ID != "" {
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			tSnap, found := ctrl.Manager.GetTask(res.ID)
			if found && (tSnap.Status == download.StatusCompleted || tSnap.Status == download.StatusFailed || tSnap.Status == download.StatusCancelled) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func TestDownloadController_CancelAndParse(t *testing.T) {
	e, _, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	// Test ParseLink for magnet
	magURI := "magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=my_video.mp4"
	parseBody, _ := json.Marshal(map[string]string{"url": magURI})
	reqParse := httptest.NewRequest(http.MethodPost, "/api/downloads/parse", bytes.NewReader(parseBody))
	reqParse.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recParse := httptest.NewRecorder()
	e.ServeHTTP(recParse, reqParse)

	if recParse.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for ParseLink, got %d", recParse.Code)
	}

	var parseRes map[string]interface{}
	json.Unmarshal(recParse.Body.Bytes(), &parseRes)
	if parseRes["name"] != "my_video.mp4" || parseRes["type"] != "magnet" {
		t.Errorf("Unexpected parse response: %v", parseRes)
	}

	// Test CancelDownload
	cancelReq := httptest.NewRequest(http.MethodDelete, "/api/downloads/non_existent_id", nil)
	cancelRec := httptest.NewRecorder()
	e.ServeHTTP(cancelRec, cancelReq)

	if cancelRec.Code != http.StatusNotFound {
		t.Errorf("Expected 404 for cancelling non-existent task, got %d", cancelRec.Code)
	}
}

func TestDownloadController_StartDownload_WithFilenameOverride(t *testing.T) {
	e, ctrl, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	payload := map[string]string{
		"url":       fs.URL + "/remote_file.bin",
		"folder_id": "f1",
		"filename":  "custom_document.pdf",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/downloads", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("Expected HTTP 202, got %d", rec.Code)
	}

	var res download.DownloadTask
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res.Filename != "custom_document.pdf" {
		t.Errorf("Expected initial filename 'custom_document.pdf', got %q", res.Filename)
	}

	// Wait for completion
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		tSnap, found := ctrl.Manager.GetTask(res.ID)
		if found && tSnap.Status == download.StatusCompleted {
			if tSnap.Filename != "custom_document.pdf" {
				t.Errorf("Expected completed filename 'custom_document.pdf', got %q", tSnap.Filename)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDownloadController_StartBatchDownload(t *testing.T) {
	e, ctrl, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	payload := map[string]interface{}{
		"input":     fs.URL + "/file_[1-2].bin",
		"folder_id": "f1",
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/api/downloads/batch", bytes.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("Expected HTTP 202, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Count int                      `json:"count"`
		Tasks []*download.DownloadTask `json:"tasks"`
	}
	json.Unmarshal(rec.Body.Bytes(), &res)

	if res.Count != 2 || len(res.Tasks) != 2 {
		t.Errorf("Expected 2 batch tasks, got count=%d, len=%d", res.Count, len(res.Tasks))
	}

	// Wait for batch tasks to finish to prevent goroutines from writing to t.TempDir() after test completes
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		allDone := true
		for _, task := range res.Tasks {
			tSnap, found := ctrl.Manager.GetTask(task.ID)
			if found && tSnap.Status != download.StatusCompleted && tSnap.Status != download.StatusFailed && tSnap.Status != download.StatusCancelled {
				allDone = false
				break
			}
		}
		if allDone {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestDownloadController_ParseLink_DeepProbeAndGoogleDrive(t *testing.T) {
	e, _, fs := setupDownloadControllerTest(t)
	defer fs.Close()

	// 1. Test Deep Probe with mock server
	parseBody, _ := json.Marshal(map[string]string{"url": fs.URL + "/remote_file.bin"})
	req := httptest.NewRequest(http.MethodPost, "/api/downloads/parse", bytes.NewReader(parseBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for deep probe, got %d", rec.Code)
	}

	var res map[string]interface{}
	json.Unmarshal(rec.Body.Bytes(), &res)
	if res["name"] != "remote_file.bin" {
		t.Errorf("Expected name 'remote_file.bin', got %v", res["name"])
	}
	if res["file_size"] == nil || res["formatted_size"] == nil {
		t.Errorf("Expected file_size and formatted_size to be present")
	}

	// 2. Test Google Drive URL resolution
	gdriveBody, _ := json.Marshal(map[string]string{"url": "https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs/view?usp=sharing"})
	reqGD := httptest.NewRequest(http.MethodPost, "/api/downloads/parse", bytes.NewReader(gdriveBody))
	reqGD.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recGD := httptest.NewRecorder()
	e.ServeHTTP(recGD, reqGD)

	if recGD.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK for Google Drive parse, got %d", recGD.Code)
	}

	var resGD map[string]interface{}
	json.Unmarshal(recGD.Body.Bytes(), &resGD)
	if resGD["provider"] != "Google Drive" {
		t.Errorf("Expected provider 'Google Drive', got %v", resGD["provider"])
	}
	resolvedURL, _ := resGD["resolved_url"].(string)
	if !strings.Contains(resolvedURL, "export=download") || !strings.Contains(resolvedURL, "id=1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs") {
		t.Errorf("Expected Google Drive direct download URL, got %q", resolvedURL)
	}
}
