package controllers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/labstack/echo/v5"
	_ "github.com/mattn/go-sqlite3"
	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/reconcile"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
)

func setupTestReconcileController(t *testing.T) (*ReconcileController, *echo.Echo, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "reconcile_ctrl_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}

	dbEngine, err := data.NewDBEngine("sqlite3", filepath.Join(tmpDir, "test.db"))
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	schema := `
	CREATE TABLE folders (
		id TEXT PRIMARY KEY,
		owner_id INTEGER NOT NULL,
		parent_id TEXT,
		name TEXT NOT NULL
	);
	CREATE TABLE files (
		id TEXT PRIMARY KEY,
		owner_id INTEGER NOT NULL,
		folder_id TEXT,
		name TEXT NOT NULL,
		mime_type TEXT NOT NULL,
		size BIGINT NOT NULL,
		cas_hash TEXT NOT NULL,
		plaintext_hash TEXT DEFAULT '',
		is_deleted BOOLEAN DEFAULT FALSE
	);
	`
	if _, err := dbEngine.SQL.Exec(schema); err != nil {
		t.Fatalf("failed to exec schema: %v", err)
	}

	casEngine, err := storage.NewCASEngine(filepath.Join(tmpDir, "cas"))
	if err != nil {
		t.Fatalf("failed to init cas: %v", err)
	}

	sm, err := upload.NewSessionManager(filepath.Join(tmpDir, "tmp"))
	if err != nil {
		t.Fatalf("failed to init session manager: %v", err)
	}

	fileCtrl := &FileController{
		DB:  dbEngine,
		CAS: casEngine,
	}

	rc := &ReconcileController{
		DB:         dbEngine,
		SessionMgr: sm,
		CAS:        casEngine,
		FileCtrl:   fileCtrl,
		QuotaBytes: 0,
	}

	e := echo.New()

	cleanup := func() {
		_ = dbEngine.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return rc, e, cleanup
}

func TestReconcileController_DiffTree_Success(t *testing.T) {
	rc, e, cleanup := setupTestReconcileController(t)
	defer cleanup()

	tree := &reconcile.MerkleNode{
		Name: "TestFolder",
		Type: reconcile.NodeDir,
		Children: []*reconcile.MerkleNode{
			{Name: "file1.txt", Type: reconcile.NodeFile, Size: 1024, MimeType: "text/plain"},
		},
	}

	payload := ReconcileTreeRequest{
		TargetFolderID: "",
		RootName:       "TestFolder",
		Tree:           tree,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/reconcile/tree-diff", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user_id", int64(1))

	err := rc.DiffTree(c)
	if err != nil {
		t.Fatalf("DiffTree returned error: %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d. Body: %s", rec.Code, rec.Body.String())
	}

	var plan reconcile.ReconciliationPlan
	if err := json.Unmarshal(rec.Body.Bytes(), &plan); err != nil {
		t.Fatalf("Failed to parse response plan: %v", err)
	}

	if plan.Status != "diff_ready" {
		t.Errorf("Expected status diff_ready, got %s", plan.Status)
	}
	if plan.Summary.TotalFiles != 1 {
		t.Errorf("Expected 1 total file, got %d", plan.Summary.TotalFiles)
	}
	if plan.Summary.MissingFiles != 1 {
		t.Errorf("Expected 1 missing file, got %d", plan.Summary.MissingFiles)
	}
}

func TestReconcileController_DiffTree_MissingTree(t *testing.T) {
	rc, e, cleanup := setupTestReconcileController(t)
	defer cleanup()

	payload := map[string]interface{}{
		"target_folder_id": "f1",
	}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/reconcile/tree-diff", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user_id", int64(1))

	err := rc.DiffTree(c)
	if err == nil {
		t.Fatalf("Expected error for missing tree, got nil")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusBadRequest {
		t.Fatalf("Expected 400 Bad Request, got %+v", err)
	}
}

func TestReconcileController_DiffTree_QuotaExceeded(t *testing.T) {
	rc, e, cleanup := setupTestReconcileController(t)
	defer cleanup()

	rc.QuotaBytes = 500 // 500 bytes quota

	tree := &reconcile.MerkleNode{
		Name: "HugeFolder",
		Type: reconcile.NodeDir,
		Children: []*reconcile.MerkleNode{
			{Name: "big.bin", Type: reconcile.NodeFile, Size: 1000},
		},
	}

	payload := ReconcileTreeRequest{
		TargetFolderID: "",
		RootName:       "HugeFolder",
		Tree:           tree,
	}

	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/reconcile/tree-diff", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)
	c.Set("user_id", int64(1))

	err := rc.DiffTree(c)
	if err == nil {
		t.Fatalf("Expected quota exceeded error, got nil")
	}
	he, ok := err.(*echo.HTTPError)
	if !ok || he.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("Expected 413 Request Entity Too Large, got %+v", err)
	}
}
