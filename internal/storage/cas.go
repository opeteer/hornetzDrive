package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

// CASEngine manages the physical Content-Addressable Storage.
// Files are stored based on their SHA-256 hash, enabling 0-second deduplication.
type CASEngine struct {
	BaseDir string
}

func NewCASEngine(baseDir string) (*CASEngine, error) {
	if err := os.MkdirAll(baseDir, 0700); err != nil {
		return nil, err
	}
	return &CASEngine{BaseDir: baseDir}, nil
}

func (c *CASEngine) Exists(hash string) bool {
	_, err := os.Stat(c.Path(hash))
	return err == nil
}

func (c *CASEngine) Path(hash string) string {
	if len(hash) < 4 {
		return filepath.Join(c.BaseDir, hash)
	}
	// Path Shuffling / Obfuscation (e.g., ab/cd/abcdef...)
	dir := filepath.Join(c.BaseDir, hash[0:2], hash[2:4])
	os.MkdirAll(dir, 0700)
	return filepath.Join(dir, hash)
}

// ComputeHash computes the SHA-256 hash of a file on disk
func ComputeHash(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// MoveToCAS moves a temporary file into the CAS storage layer, renaming it to its SHA-256 hash.
func (c *CASEngine) MoveToCAS(tempPath string) (string, error) {
	hash, err := ComputeHash(tempPath)
	if err != nil {
		return "", err
	}

	destPath := c.Path(hash)
	if c.Exists(hash) {
		// Dedup: file already exists, we can safely delete the temp file
		os.Remove(tempPath)
		return hash, nil
	}

	if err := os.Rename(tempPath, destPath); err != nil {
		return "", err
	}
	return hash, nil
}
