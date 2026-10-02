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

func TestCASEngine_HashValidationAndTraversal(t *testing.T) {
	// Test valid 64-char hex
	validHash := "a8f3b2c91d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567"
	if !IsValidHash(validHash) {
		t.Errorf("Expected IsValidHash(%q) to be true", validHash)
	}

	// Test invalid hashes
	invalidHashes := []string{
		"../../etc/passwd",
		"../..",
		"/root",
		"short_hash",
		"g8f3b2c91d4e5f67890abcdef1234567890abcdef1234567890abcdef123456z",
		"",
	}
	for _, h := range invalidHashes {
		if IsValidHash(h) {
			t.Errorf("Expected IsValidHash(%q) to be false", h)
		}
	}

	// Verify cas.Path and cas.Exists with traversal attacks
	tempDir := t.TempDir()
	cas, err := NewCASEngine(tempDir)
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	for _, h := range invalidHashes {
		if cas.Exists(h) {
			t.Errorf("Expected cas.Exists(%q) to be false", h)
		}
	}
}
