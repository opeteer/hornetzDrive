package controllers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/download"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/realtime"
)

func TestSecurityController_PanicPurge(t *testing.T) {
	e := echo.New()
	baseDir := t.TempDir()
	casEngine, err := storage.NewCASEngine(baseDir)
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	// 1. Populate RAM Key
	sessionID := "test-purge-session"
	auth.GlobalSessionStore.SetKey(sessionID, crypto.DummyVK())

	// 2. Write dummy file to CAS
	dummyPath := casEngine.Path("dummy_hash_for_test")
	os.MkdirAll(filepath.Dir(dummyPath), 0700)
	os.WriteFile(dummyPath, []byte("sensitive payload"), 0644)

	secCtrl := &SecurityController{
		CAS:    casEngine,
		Broker: realtime.NewMemoryBroker(),
	}

	// Unauthenticated request should be rejected (401)
	unauthReq := httptest.NewRequest(http.MethodPost, "/api/purge", nil)
	unauthRec := httptest.NewRecorder()
	unauthC := e.NewContext(unauthReq, unauthRec)
	err = secCtrl.PanicPurge(unauthC)
	if err == nil {
		t.Fatalf("Expected error for unauthenticated purge, got nil")
	}
	if he, ok := err.(*echo.HTTPError); !ok || he.Code != http.StatusUnauthorized {
		t.Fatalf("Expected HTTP 401 echo.HTTPError, got %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/purge", nil)
	req.AddCookie(&http.Cookie{Name: "swarm_session", Value: sessionID})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := secCtrl.PanicPurge(c); err != nil {
		t.Fatalf("PanicPurge failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d", rec.Code)
	}

	// Verify RAM keys obliterated
	_, exists := auth.GlobalSessionStore.GetKey(sessionID)
	if exists {
		t.Fatalf("Session key should be deleted after Panic Purge")
	}

	// Verify File deleted
	if _, err := os.Stat(dummyPath); !os.IsNotExist(err) {
		t.Fatalf("Physical CAS file should be shredded and unlinked")
	}
}

func TestSecurityController_PanicPurge_CompleteShredAndDownloadAbort(t *testing.T) {
	e := echo.New()
	baseDir := t.TempDir()
	casEngine, err := storage.NewCASEngine(baseDir)
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	tmpDir := t.TempDir()
	// Create a temp file and a CAS shard directory with a file
	tempFilePath := filepath.Join(tmpDir, "upload_temp_123.bin")
	_ = os.WriteFile(tempFilePath, []byte("in-flight temp buffer"), 0600)

	casShardDir := filepath.Join(baseDir, "ab", "cd")
	_ = os.MkdirAll(casShardDir, 0700)
	casFilePath := filepath.Join(casShardDir, "abcdef1234567890.dat")
	_ = os.WriteFile(casFilePath, []byte("sensitive cas shard"), 0600)

	broker := realtime.NewMemoryBroker()
	downloadMgr, err := download.NewDownloadManager(casEngine, nil, broker, tmpDir, 0)
	if err != nil {
		t.Fatalf("Failed to init DownloadManager: %v", err)
	}

	// Create an active download task
	task, err := downloadMgr.StartDownload(context.Background(), 1, "f1", "http://127.0.0.1:9999/nonexistent.iso", false, nil)
	if err != nil {
		t.Fatalf("Failed to start download task: %v", err)
	}

	sessionID := "test-purge-sess-2"
	auth.GlobalSessionStore.SetKey(sessionID, crypto.DummyVK())

	secCtrl := &SecurityController{
		CAS:         casEngine,
		Broker:      broker,
		TmpDir:      tmpDir,
		DownloadMgr: downloadMgr,
	}

	req := httptest.NewRequest(http.MethodPost, "/api/purge", nil)
	req.AddCookie(&http.Cookie{Name: "swarm_session", Value: sessionID})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := secCtrl.PanicPurge(c); err != nil {
		t.Fatalf("PanicPurge failed: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200, got %d", rec.Code)
	}

	// Verify temp file shredded and removed
	if _, err := os.Stat(tempFilePath); !os.IsNotExist(err) {
		t.Errorf("Temp file should be deleted after PanicPurge")
	}

	// Verify CAS file shredded and removed
	if _, err := os.Stat(casFilePath); !os.IsNotExist(err) {
		t.Errorf("CAS file should be deleted after PanicPurge")
	}

	// Verify empty CAS shard directory pruned
	if _, err := os.Stat(casShardDir); !os.IsNotExist(err) {
		t.Errorf("Empty CAS shard directory should be pruned after PanicPurge")
	}

	// Verify download task was cancelled
	snap, found := downloadMgr.GetTask(task.ID)
	if !found || snap.Status != download.StatusCancelled {
		t.Errorf("Download task should be StatusCancelled, got %+v", snap)
	}
}
