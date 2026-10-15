package reconcile

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/upload"
)

func TestMerkle_DeterministicHash(t *testing.T) {
	// Tree 1: children added in order A, B
	tree1 := &MerkleNode{
		Name: "test_dir",
		Type: NodeDir,
		Children: []*MerkleNode{
			{Name: "file_a.txt", Type: NodeFile, Size: 100, Hash: "hash_a"},
			{Name: "file_b.txt", Type: NodeFile, Size: 200, Hash: "hash_b"},
		},
	}
	hash1 := tree1.ComputeDirectoryHash()

	// Tree 2: children added in reverse order B, A
	tree2 := &MerkleNode{
		Name: "test_dir",
		Type: NodeDir,
		Children: []*MerkleNode{
			{Name: "file_b.txt", Type: NodeFile, Size: 200, Hash: "hash_b"},
			{Name: "file_a.txt", Type: NodeFile, Size: 100, Hash: "hash_a"},
		},
	}
	hash2 := tree2.ComputeDirectoryHash()

	if hash1 != hash2 {
		t.Fatalf("Deterministic hashing failed: hash1=%s != hash2=%s", hash1, hash2)
	}

	// Tree 3: different child content
	tree3 := &MerkleNode{
		Name: "test_dir",
		Type: NodeDir,
		Children: []*MerkleNode{
			{Name: "file_a.txt", Type: NodeFile, Size: 101, Hash: "hash_a_diff"},
			{Name: "file_b.txt", Type: NodeFile, Size: 200, Hash: "hash_b"},
		},
	}
	hash3 := tree3.ComputeDirectoryHash()

	if hash1 == hash3 {
		t.Fatalf("Hash collision: differing trees produced identical hash: %s", hash1)
	}
}

func TestMerkle_CountStats(t *testing.T) {
	tree := &MerkleNode{
		Name: "root",
		Type: NodeDir,
		Children: []*MerkleNode{
			{Name: "f1.txt", Type: NodeFile, Size: 150},
			{
				Name: "sub",
				Type: NodeDir,
				Children: []*MerkleNode{
					{Name: "f2.txt", Type: NodeFile, Size: 250},
					{Name: "f3.txt", Type: NodeFile, Size: 350},
				},
			},
		},
	}

	count, bytes := tree.CountStats()
	if count != 3 {
		t.Errorf("Expected 3 files, got %d", count)
	}
	if bytes != 750 {
		t.Errorf("Expected 750 bytes, got %d", bytes)
	}
}

func setupTestDB(t *testing.T) (*data.DBEngine, func()) {
	t.Helper()
	tmpDir, err := os.MkdirTemp("", "reconcile_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatalf("failed to open sqlite: %v", err)
	}

	// Create tables
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
	if _, err := db.Exec(schema); err != nil {
		t.Fatalf("failed to exec schema: %v", err)
	}

	engine := &data.DBEngine{
		DriverName: "sqlite3",
		SQL:        db,
	}

	cleanup := func() {
		_ = db.Close()
		_ = os.RemoveAll(tmpDir)
	}

	return engine, cleanup
}

func TestReconcile_RootMerkleMatch(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	// Seed remote folder and file
	_, err := db.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_root', 1, NULL, 'MyProject')")
	if err != nil {
		t.Fatalf("seed folder failed: %v", err)
	}
	_, err = db.SQL.Exec("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, plaintext_hash) VALUES ('fl_1', 1, 'f_root', 'main.go', 'text/plain', 500, 'hash1', 'hash1')")
	if err != nil {
		t.Fatalf("seed file failed: %v", err)
	}

	// Build matching client tree
	clientTree := &MerkleNode{
		Name: "MyProject",
		Type: NodeDir,
		Children: []*MerkleNode{
			{Name: "main.go", Type: NodeFile, Size: 500, Hash: "hash1"},
		},
	}

	plan, err := ReconcileTree(clientTree, nil, db, 1, "")
	if err != nil {
		t.Fatalf("ReconcileTree error: %v", err)
	}

	if !plan.RootSynced {
		t.Errorf("Expected RootSynced to be true")
	}
	if plan.Summary.AlreadySyncedFiles != 1 {
		t.Errorf("Expected 1 already synced file, got %d", plan.Summary.AlreadySyncedFiles)
	}
	if plan.Summary.BytesRemaining != 0 {
		t.Errorf("Expected 0 bytes remaining, got %d", plan.Summary.BytesRemaining)
	}
	if len(plan.Actions) != 1 || plan.Actions[0].Action != ActionSkip {
		t.Fatalf("Expected 1 SKIP action, got %+v", plan.Actions)
	}
}

func TestReconcile_SubtreePruningAndResume(t *testing.T) {
	db, cleanup := setupTestDB(t)
	defer cleanup()

	tmpDir, err := os.MkdirTemp("", "sess_test_*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sm, err := upload.NewSessionManager(tmpDir)
	if err != nil {
		t.Fatalf("failed to init session manager: %v", err)
	}

	// Seed existing folder structure:
	// MyProject (f_root)
	//   ├── SubCompleted (f_sub)
	//   │     └── doc.pdf (size: 2000)
	_, _ = db.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_root', 1, NULL, 'MyProject')")
	_, _ = db.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_sub', 1, 'f_root', 'SubCompleted')")
	_, _ = db.SQL.Exec("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, plaintext_hash) VALUES ('fl_doc', 1, 'f_sub', 'doc.pdf', 'application/pdf', 2000, 'h_doc', 'h_doc')")

	// Create an incomplete upload session for a large video in MyProject
	largeSess, err := sm.CreateSession(1, "f_root", "video.mp4", "video/mp4", 10000)
	if err != nil {
		t.Fatalf("failed to create session: %v", err)
	}
	largeSess.UploadedSize = 6000 // 60% uploaded
	_ = sm.PersistSession(largeSess)

	// Client tree:
	// MyProject
	//   ├── SubCompleted (matches server hash exactly)
	//   │     └── doc.pdf (size: 2000)
	//   ├── video.mp4 (size: 10000, half-uploaded)
	//   └── new_file.txt (size: 500, missing)
	clientTree := &MerkleNode{
		Name: "MyProject",
		Type: NodeDir,
		Children: []*MerkleNode{
			{
				Name: "SubCompleted",
				Type: NodeDir,
				Children: []*MerkleNode{
					{Name: "doc.pdf", Type: NodeFile, Size: 2000, Hash: "h_doc"},
				},
			},
			{Name: "video.mp4", Type: NodeFile, Size: 10000, Hash: "h_video"},
			{Name: "new_file.txt", Type: NodeFile, Size: 500, Hash: "h_new"},
		},
	}

	plan, err := ReconcileTree(clientTree, sm, db, 1, "")
	if err != nil {
		t.Fatalf("ReconcileTree error: %v", err)
	}

	if plan.RootSynced {
		t.Errorf("Expected RootSynced to be false")
	}

	// Verify stats
	if plan.Summary.TotalFiles != 3 {
		t.Errorf("Expected 3 total files, got %d", plan.Summary.TotalFiles)
	}
	if plan.Summary.AlreadySyncedFiles != 1 {
		t.Errorf("Expected 1 already synced file (from SubCompleted), got %d", plan.Summary.AlreadySyncedFiles)
	}
	if plan.Summary.ResumableFiles != 1 {
		t.Errorf("Expected 1 resumable file, got %d", plan.Summary.ResumableFiles)
	}
	if plan.Summary.MissingFiles != 1 {
		t.Errorf("Expected 1 missing file, got %d", plan.Summary.MissingFiles)
	}
	// Bytes remaining: 4000 (from video) + 500 (from new_file) = 4500
	if plan.Summary.BytesRemaining != 4500 {
		t.Errorf("Expected 4500 bytes remaining, got %d", plan.Summary.BytesRemaining)
	}

	// Check actions
	var foundSkipSub, foundResumeVideo, foundUploadNew bool
	for _, act := range plan.Actions {
		if act.Action == ActionSkip && act.Name == "SubCompleted" && act.Reason == "subtree_merkle_match" {
			foundSkipSub = true
			if act.PrunedCount != 1 || act.BytesSaved != 2000 {
				t.Errorf("Incorrect SubCompleted pruned count or bytes: %+v", act)
			}
		}
		if act.Action == ActionResume && act.Name == "video.mp4" {
			foundResumeVideo = true
			if act.SessionID != largeSess.ID || act.UploadedBytes != 6000 || act.TotalSize != 10000 {
				t.Errorf("Incorrect video.mp4 resume details: %+v", act)
			}
		}
		if act.Action == ActionUploadNew && act.Name == "new_file.txt" {
			foundUploadNew = true
			if act.TotalSize != 500 {
				t.Errorf("Incorrect new_file.txt size: %+v", act)
			}
		}
	}

	if !foundSkipSub {
		t.Errorf("Expected SKIP action for SubCompleted subtree")
	}
	if !foundResumeVideo {
		t.Errorf("Expected RESUME action for video.mp4")
	}
	if !foundUploadNew {
		t.Errorf("Expected UPLOAD_NEW action for new_file.txt")
	}
}
