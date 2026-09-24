package fullstack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Manifest represents the mapping from original asset names to content-hashed asset names.
// e.g., "js/app.js" -> "js/app.a8f9b2.js"
type Manifest map[string]string

// GenerateManifest walks the provided output directory, generates SHA-256 content hashes
// for all files, renames them with the hash, and writes a manifest.json file.
func GenerateManifest(outDir string) (Manifest, error) {
	manifest := make(Manifest)

	err := filepath.Walk(outDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || filepath.Base(path) == "manifest.json" {
			return nil
		}

		// Calculate SHA-256 hash
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		hasher := sha256.New()
		if _, err := io.Copy(hasher, f); err != nil {
			return err
		}
		hashString := hex.EncodeToString(hasher.Sum(nil))[:8] // Short 8-char hash

		// Generate hashed filename: app.js -> app.a8f9b2.js
		dir := filepath.Dir(path)
		ext := filepath.Ext(path)
		baseName := strings.TrimSuffix(filepath.Base(path), ext)
		hashedName := fmt.Sprintf("%s.%s%s", baseName, hashString, ext)
		hashedPath := filepath.Join(dir, hashedName)

		// Rename file
		f.Close() // Close before rename
		if err := os.Rename(path, hashedPath); err != nil {
			return err
		}

		// Compute relative paths for manifest
		relOriginal, _ := filepath.Rel(outDir, path)
		relHashed, _ := filepath.Rel(outDir, hashedPath)

		// Normalize paths to forward slashes for URLs
		manifest[filepath.ToSlash(relOriginal)] = filepath.ToSlash(relHashed)

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Write manifest.json
	manifestPath := filepath.Join(outDir, "manifest.json")
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return nil, err
	}

	return manifest, nil
}

// LoadManifest reads a manifest.json file from the given file system (usually embed.FS).
func LoadManifest(fileSystem fs.FS, manifestPath string) (Manifest, error) {
	f, err := fileSystem.Open(manifestPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, err
	}

	return manifest, nil
}
