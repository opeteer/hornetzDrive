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
