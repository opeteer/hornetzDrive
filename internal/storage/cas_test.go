package storage

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

func TestCASEngine_ExistsDoesNotCreateDirectories(t *testing.T) {
	tempDir := t.TempDir()
	cas, err := NewCASEngine(tempDir)
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	fakeHash := "deadbeef00000000000000000000000000000000000000000000000000000000"
	if cas.Exists(fakeHash) {
		t.Fatalf("Non-existent hash should return false")
	}

	expectedSubdir := filepath.Join(tempDir, "de", "ad")
	if _, err := os.Stat(expectedSubdir); !os.IsNotExist(err) {
		t.Fatalf("c.Exists() created directory %s on disk!", expectedSubdir)
	}
}

func TestCASEngine_TotalCapacity(t *testing.T) {
	tempDir := t.TempDir()
	cas, err := NewCASEngine(tempDir)
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	capBytes, err := cas.TotalCapacity()
	if err != nil {
		t.Fatalf("TotalCapacity failed: %v", err)
	}
	if capBytes <= 0 {
		t.Fatalf("Expected TotalCapacity > 0, got %d", capBytes)
	}

	// Test fallback when BaseDir does not exist yet
	nonExistentCas := &CASEngine{BaseDir: filepath.Join(tempDir, "non_existent_subdir")}
	capFallback, err := nonExistentCas.TotalCapacity()
	if err != nil {
		t.Fatalf("TotalCapacity with non-existent dir failed: %v", err)
	}
	if capFallback <= 0 {
		t.Fatalf("Expected fallback TotalCapacity > 0, got %d", capFallback)
	}
}

func TestChitinShuffler_TimelineJitter(t *testing.T) {
	tempDir := t.TempDir()
	cas, err := NewCASEngine(tempDir)
	if err != nil {
		t.Fatalf("Failed to init CAS: %v", err)
	}

	// Create 3 dummy CAS files
	f1 := cas.Path("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f2 := cas.Path("1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	f3 := cas.Path("2123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	_ = os.MkdirAll(filepath.Dir(f1), 0755)
	_ = os.MkdirAll(filepath.Dir(f2), 0755)
	_ = os.MkdirAll(filepath.Dir(f3), 0755)

	_ = os.WriteFile(f1, []byte("data1"), 0644)
	_ = os.WriteFile(f2, []byte("data2"), 0644)
	_ = os.WriteFile(f3, []byte("data3"), 0644)

	shuffler := &ChitinShuffler{CAS: cas}
	shuffler.ShufflePaths()

	info1, err := os.Stat(f1)
	if err != nil {
		t.Fatalf("Stat f1 failed: %v", err)
	}
	info2, err := os.Stat(f2)
	if err != nil {
		t.Fatalf("Stat f2 failed: %v", err)
	}
	info3, err := os.Stat(f3)
	if err != nil {
		t.Fatalf("Stat f3 failed: %v", err)
	}

	now := time.Now()
	// All timestamps must be in the past (at least 30 minutes in the past, within 8 days)
	for _, fi := range []os.FileInfo{info1, info2, info3} {
		diff := now.Sub(fi.ModTime())
		if diff < 30*time.Minute || diff > 8*24*time.Hour {
			t.Errorf("ModTime %v not properly jittered in the past: diff=%v", fi.ModTime(), diff)
		}
	}

	// Timestamps must not all be identical (decorrelated)
	if info1.ModTime().Equal(info2.ModTime()) && info2.ModTime().Equal(info3.ModTime()) {
		t.Errorf("Timestamps across files should be decorrelated, but all equal: %v", info1.ModTime())
	}
}
