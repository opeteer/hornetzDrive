package fullstack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBundleAssets(t *testing.T) {
	// Create a temporary directory for testing
	tmpDir, err := os.MkdirTemp("", "ztatic-esbuild-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create a dummy JS file
	entryFile := filepath.Join(tmpDir, "app.js")
	err = os.WriteFile(entryFile, []byte("console.log('hello world');"), 0644)
	if err != nil {
		t.Fatalf("Failed to write entry file: %v", err)
	}

	outDir := filepath.Join(tmpDir, "dist")

	opts := BundlerOptions{
		EntryPoints:  []string{entryFile},
		OutDir:       outDir,
		IsProduction: true,
	}

	result, err := BundleAssets(opts)
	if err != nil {
		t.Fatalf("BundleAssets failed: %v", err)
	}

	if result == nil {
		t.Fatalf("Expected build result, got nil")
	}

	// Verify output exists
	outFile := filepath.Join(outDir, "app.js")
	if _, err := os.Stat(outFile); os.IsNotExist(err) {
		t.Errorf("Expected output file %s to exist, but it doesn't", outFile)
	}
}

func TestBundleAssets_ErrorHandling(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "ztatic-esbuild-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	entryFile := filepath.Join(tmpDir, "app.js")
	// Write invalid JS syntax
	err = os.WriteFile(entryFile, []byte("console.log('missing quote);"), 0644)
	if err != nil {
		t.Fatalf("Failed to write entry file: %v", err)
	}

	outDir := filepath.Join(tmpDir, "dist")

	opts := BundlerOptions{
		EntryPoints:  []string{entryFile},
		OutDir:       outDir,
		IsProduction: true,
	}

	_, err = BundleAssets(opts)
	if err == nil {
		t.Fatalf("Expected BundleAssets to fail due to syntax error, but it succeeded")
	}

	bundleErr, ok := err.(*AssetBundleError)
	if !ok {
		t.Fatalf("Expected err to be of type *AssetBundleError, got %T", err)
	}

	if filepath.Base(bundleErr.File) != filepath.Base(entryFile) {
		t.Errorf("Expected error file to match %s, got %s", filepath.Base(entryFile), bundleErr.File)
	}
}
