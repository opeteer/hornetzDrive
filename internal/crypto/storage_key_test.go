package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestStandardStorageKey_InitWithConfiguredKey(t *testing.T) {
	key, err := InitStandardStorageKey("super_secret_master_key_12345", "")
	if err != nil {
		t.Fatalf("InitStandardStorageKey failed: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}

	got := GetStandardStorageKey()
	if !bytes.Equal(key, got) {
		t.Fatalf("GetStandardStorageKey mismatch: expected %x, got %x", key, got)
	}
}

func TestStandardStorageKey_PersistedFile(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "hornetz_key_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	key1, err := InitStandardStorageKey("", tmpDir)
	if err != nil {
		t.Fatalf("InitStandardStorageKey failed: %v", err)
	}

	keyPath := filepath.Join(tmpDir, ".master_key")
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		t.Fatalf("expected .master_key to be created at %s", keyPath)
	}

	// Reset standardKey in memory and re-read from disk
	standardKeyMu.Lock()
	standardKey = nil
	standardKeyMu.Unlock()

	key2, err := InitStandardStorageKey("", tmpDir)
	if err != nil {
		t.Fatalf("second InitStandardStorageKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatalf("keys should match after reload: key1=%x, key2=%x", key1, key2)
	}
}
