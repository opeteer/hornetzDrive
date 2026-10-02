package upload

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionManager_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	sm, err := NewSessionManager(tempDir)
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}

	sess, err := sm.CreateSession(1, "root", "sample.txt", "text/plain", 100)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	if sess.ID == "" {
		t.Fatalf("Expected non-empty session ID")
	}

	// Verify temp file exists
	if _, err := os.Stat(sess.TempFilePath); os.IsNotExist(err) {
		t.Fatalf("Expected temp file %s to exist", sess.TempFilePath)
	}

	// Get session
	retrieved, ok := sm.GetSession(sess.ID)
	if !ok || retrieved.ID != sess.ID {
		t.Fatalf("GetSession failed or returned wrong session")
	}

	// Delete session
	sm.DeleteSession(sess.ID)
	if _, ok := sm.GetSession(sess.ID); ok {
		t.Fatalf("Expected session to be deleted")
	}
	if _, err := os.Stat(sess.TempFilePath); !os.IsNotExist(err) {
		t.Fatalf("Expected temp file to be removed after DeleteSession")
	}
}

func TestSessionManager_CleanupStaleSessions(t *testing.T) {
	tempDir := t.TempDir()
	sm, err := NewSessionManager(tempDir)
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}

	sess1, err := sm.CreateSession(1, "root", "active.txt", "text/plain", 100)
	if err != nil {
		t.Fatalf("CreateSession active failed: %v", err)
	}

	sess2, err := sm.CreateSession(1, "root", "stale.txt", "text/plain", 100)
	if err != nil {
		t.Fatalf("CreateSession stale failed: %v", err)
	}

	// Backdate sess2 LastActiveAt by 2 hours
	sm.mu.Lock()
	sess2.LastActiveAt = time.Now().Add(-2 * time.Hour)
	sm.mu.Unlock()

	cleaned := sm.CleanupStaleSessions(1 * time.Hour)
	if cleaned != 1 {
		t.Fatalf("Expected 1 stale session cleaned, got %d", cleaned)
	}

	// sess1 should still exist
	if _, ok := sm.GetSession(sess1.ID); !ok {
		t.Fatalf("Active session sess1 should not have been cleaned")
	}

	// sess2 should be gone, including its temp file
	if _, ok := sm.GetSession(sess2.ID); ok {
		t.Fatalf("Stale session sess2 should have been deleted")
	}
	if _, err := os.Stat(filepath.Join(tempDir, "upload_"+sess2.ID+".tmp")); !os.IsNotExist(err) {
		t.Fatalf("Expected stale temp file to be deleted")
	}
}
