package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkCASDeduplication(b *testing.B) {
	tempDir := b.TempDir()
	cas, err := NewCASEngine(tempDir)
	if err != nil {
		b.Fatalf("Failed to init CAS: %v", err)
	}

	payload := []byte("hornetz drive swarm vault high throughput payload deduplication test")
	testFile := filepath.Join(b.TempDir(), "bench_upload.tmp")
	os.WriteFile(testFile, payload, 0644)

	// Pre-seed CAS
	hash, err := cas.MoveToCAS(testFile)
	if err != nil {
		b.Fatalf("MoveToCAS failed: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Benchmark 0-second instant upload deduplication check
		if !cas.Exists(hash) {
			b.Fatal("Expected hash to exist in CAS")
		}
	}
}
