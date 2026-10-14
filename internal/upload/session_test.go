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

func TestSessionManager_FindActiveSession(t *testing.T) {
	tempDir := t.TempDir()
	sm, err := NewSessionManager(tempDir)
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}

	sess, err := sm.CreateSession(1, "f1", "large_video.mp4", "video/mp4", 1000)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// 1. Initially UploadedSize == 0, still should be found as active unfinished session
	found, ok := sm.FindActiveSession(1, "f1", "large_video.mp4", 1000)
	if !ok || found.ID != sess.ID {
		t.Fatalf("Expected to find active session")
	}

	// 2. Different folder should not match
	if _, ok := sm.FindActiveSession(1, "f2", "large_video.mp4", 1000); ok {
		t.Fatalf("Different folder should not match")
	}

	// 3. Different size should not match
	if _, ok := sm.FindActiveSession(1, "f1", "large_video.mp4", 2000); ok {
		t.Fatalf("Different size should not match")
	}

	// 4. Completed session (UploadedSize == ExpectedSize) should not be returned as active unfinished session
	sm.mu.Lock()
	sess.UploadedSize = 1000
	sm.mu.Unlock()

	if _, ok := sm.FindActiveSession(1, "f1", "large_video.mp4", 1000); ok {
		t.Fatalf("Fully uploaded session should not be returned by FindActiveSession")
	}
}

func TestSessionManager_PersistenceAcrossRestarts(t *testing.T) {
	tempDir := t.TempDir()
	sm1, err := NewSessionManager(tempDir)
	if err != nil {
		t.Fatalf("NewSessionManager 1 failed: %v", err)
	}

	sess, err := sm1.CreateSession(1, "f1", "backup.tar.gz", "application/gzip", 5000)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Simulate writing some data and updating UploadedSize
	sess.UploadedSize = 2500
	if err := sm1.PersistSession(sess); err != nil {
		t.Fatalf("PersistSession failed: %v", err)
	}

	// Create a new SessionManager simulating a server restart
	sm2, err := NewSessionManager(tempDir)
	if err != nil {
		t.Fatalf("NewSessionManager 2 failed: %v", err)
	}

	reloaded, ok := sm2.GetSession(sess.ID)
	if !ok {
		t.Fatalf("Expected session %s to be reloaded after restart", sess.ID)
	}
	if reloaded.Filename != "backup.tar.gz" || reloaded.UploadedSize != 2500 || reloaded.ExpectedSize != 5000 {
		t.Fatalf("Reloaded session attributes mismatch: %+v", reloaded)
	}

	// FindActiveSession should also find the reloaded half-uploaded session
	active, ok := sm2.FindActiveSession(1, "f1", "backup.tar.gz", 5000)
	if !ok || active.ID != sess.ID {
		t.Fatalf("FindActiveSession failed on reloaded session")
	}
}

func TestSessionManager_PurgeAllCleansMetadata(t *testing.T) {
	tempDir := t.TempDir()
	sm, err := NewSessionManager(tempDir)
	if err != nil {
		t.Fatalf("NewSessionManager failed: %v", err)
	}

	sess, _ := sm.CreateSession(1, "f1", "data.bin", "application/octet-stream", 100)
	metaPath := sm.metaPath(sess.ID)
	tmpPath := sess.TempFilePath

	if _, err := os.Stat(metaPath); os.IsNotExist(err) {
		t.Fatalf("Expected meta file to exist before purge")
	}
	if _, err := os.Stat(tmpPath); os.IsNotExist(err) {
		t.Fatalf("Expected tmp file to exist before purge")
	}

	sm.PurgeAll()

	if _, err := os.Stat(metaPath); !os.IsNotExist(err) {
		t.Fatalf("Expected meta file to be removed after PurgeAll")
	}
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatalf("Expected tmp file to be removed after PurgeAll")
	}
}

