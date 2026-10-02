package controllers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
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
