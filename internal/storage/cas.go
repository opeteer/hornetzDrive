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

// IsValidHash validates that the hash is a strict 64-character hexadecimal SHA-256 string.
func IsValidHash(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for i := 0; i < len(hash); i++ {
		c := hash[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func (c *CASEngine) Exists(hash string) bool {
	if !IsValidHash(hash) {
		return false
	}
	_, err := os.Stat(c.Path(hash))
	return err == nil
}

func (c *CASEngine) Path(hash string) string {
	if !IsValidHash(hash) {
		// Prevent path traversal outside BaseDir
		return filepath.Join(c.BaseDir, "invalid_hash")
	}
	// Path Shuffling / Obfuscation (e.g., ab/cd/abcdef...)
	return filepath.Join(c.BaseDir, hash[0:2], hash[2:4], hash)
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

// MoveToCASWithStatus moves a temporary file into the CAS storage layer, renaming it to its SHA-256 hash.
// It returns the computed hash, whether the file existed before (deduped), and any error encountered.
func (c *CASEngine) MoveToCASWithStatus(tempPath string) (hash string, existedBefore bool, err error) {
	hash, err = ComputeHash(tempPath)
	if err != nil {
		return "", false, err
	}

	destPath := c.Path(hash)
	if c.Exists(hash) {
		// Dedup: file already exists, we can safely delete the temp file
		os.Remove(tempPath)
		return hash, true, nil
	}

	if err := os.MkdirAll(filepath.Dir(destPath), 0700); err != nil {
		return "", false, err
	}

	if err := os.Rename(tempPath, destPath); err != nil {
		// Fallback for cross-device links (EXDEV) when TMP_DIR and CAS_DIR are on different filesystems
		srcFile, errOpen := os.Open(tempPath)
		if errOpen != nil {
			return "", false, err
		}
		defer srcFile.Close()

		dstFile, errCreate := os.Create(destPath)
		if errCreate != nil {
			return "", false, err
		}
		defer dstFile.Close()

		if _, errCopy := io.Copy(dstFile, srcFile); errCopy != nil {
			os.Remove(destPath)
			return "", false, errCopy
		}
		_ = dstFile.Sync()
		_ = srcFile.Close()
		_ = dstFile.Close()
		_ = os.Remove(tempPath)
	}
	return hash, false, nil
}

// MoveToCAS moves a temporary file into the CAS storage layer, renaming it to its SHA-256 hash.
func (c *CASEngine) MoveToCAS(tempPath string) (string, error) {
	hash, _, err := c.MoveToCASWithStatus(tempPath)
	return hash, err
}

