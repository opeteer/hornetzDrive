package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCASEngineDeduplication(t *testing.T) {
	tempDir := t.TempDir()
	cas, err := NewCASEngine(tempDir)
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	// Create test file
	testFile := filepath.Join(t.TempDir(), "upload.tmp")
	os.WriteFile(testFile, []byte("test content"), 0644)

	// Move to CAS
	hash, err := cas.MoveToCAS(testFile)
	if err != nil {
		t.Fatalf("MoveToCAS failed: %v", err)
	}

	if !cas.Exists(hash) {
		t.Fatalf("CAS should exist for hash %s", hash)
	}

	// Test Deduplication
	testFile2 := filepath.Join(t.TempDir(), "upload2.tmp")
	os.WriteFile(testFile2, []byte("test content"), 0644)

	hash2, err := cas.MoveToCAS(testFile2)
	if err != nil {
		t.Fatalf("MoveToCAS (dedup) failed: %v", err)
	}

	if hash != hash2 {
		t.Fatalf("Hashes should match: %s != %s", hash, hash2)
	}
}
