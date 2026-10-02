package fullstack

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateAndLoadManifest(t *testing.T) {
	// Create a temporary directory structure mimicking an asset build output
	tempDir := t.TempDir()
	
	// Create test files
	jsPath := filepath.Join(tempDir, "app.js")
	cssPath := filepath.Join(tempDir, "app.css")
	
	err := os.WriteFile(jsPath, []byte("console.log('hello');"), 0644)
	if err != nil {
		t.Fatalf("failed to write test js: %v", err)
	}
	err = os.WriteFile(cssPath, []byte("body { color: red; }"), 0644)
	if err != nil {
		t.Fatalf("failed to write test css: %v", err)
	}

	// 1. Generate Manifest
	manifest, err := GenerateManifest(tempDir)
	if err != nil {
		t.Fatalf("GenerateManifest failed: %v", err)
	}

	// Verify JS was hashed (sha256 of "console.log('hello');" prefix is 1726a27e)
	hashedJS, ok := manifest["app.js"]
	if !ok {
		t.Fatalf("app.js missing from manifest")
	}
	if hashedJS == "app.js" {
		t.Errorf("app.js was not renamed with a hash")
	}
	
	// Verify files actually exist on disk with the new name
	if _, err := os.Stat(filepath.Join(tempDir, hashedJS)); os.IsNotExist(err) {
		t.Errorf("Hashed file %s does not exist on disk", hashedJS)
	}

	// 2. Load Manifest from disk
	fsys := os.DirFS(tempDir)
	loadedManifest, err := LoadManifest(fsys, "manifest.json")
	if err != nil {
		t.Fatalf("LoadManifest failed: %v", err)
	}

	if loadedManifest["app.css"] != manifest["app.css"] {
		t.Errorf("Loaded manifest css hash mismatch")
	}
}

func TestGenerateManifest_IdempotencyAndHiddenFiles(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a hidden file (.gitkeep) and normal asset (style.css)
	_ = os.WriteFile(filepath.Join(tempDir, ".gitkeep"), []byte(""), 0644)
	_ = os.WriteFile(filepath.Join(tempDir, "style.css"), []byte("body { margin: 0; }"), 0644)

	// First manifest generation
	m1, err := GenerateManifest(tempDir)
	if err != nil {
		t.Fatalf("First GenerateManifest failed: %v", err)
	}

	// Verify .gitkeep was NOT hashed or added to manifest
	if _, ok := m1[".gitkeep"]; ok {
		t.Errorf(".gitkeep should not be included in manifest")
	}
	if _, err := os.Stat(filepath.Join(tempDir, ".gitkeep")); err != nil {
		t.Errorf(".gitkeep should remain untouched")
	}

	hashedStyle1 := m1["style.css"]
	if hashedStyle1 == "" || hashedStyle1 == "style.css" {
		t.Fatalf("style.css was not hashed")
	}

	// Verify original file still exists for dev mode
	if _, err := os.Stat(filepath.Join(tempDir, "style.css")); err != nil {
		t.Errorf("original style.css should remain on disk")
	}

	// Second manifest generation (idempotency test)
	m2, err := GenerateManifest(tempDir)
	if err != nil {
		t.Fatalf("Second GenerateManifest failed: %v", err)
	}

	if m2["style.css"] != hashedStyle1 {
		t.Errorf("Expected identical hash on second run, got %s vs %s", m2["style.css"], hashedStyle1)
	}

	// Verify no double-hashed files were created (e.g. style.<hash>.<hash>.css)
	entries, _ := os.ReadDir(tempDir)
	for _, e := range entries {
		name := e.Name()
		if name == ".gitkeep" || name == "style.css" || name == hashedStyle1 || name == "manifest.json" {
			continue
		}
		t.Errorf("Unexpected extra or double-hashed file found: %s", name)
	}
}
