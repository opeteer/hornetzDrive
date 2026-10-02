package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	// ErrPathTraversal is returned when a storage key attempts to escape the root directory.
	ErrPathTraversal = errors.New("storage: path traversal detected")
	// ErrFileNotFound is returned when the requested file does not exist.
	ErrFileNotFound = errors.New("storage: file not found")
)

// LocalConfig configures the LocalStorage driver.
type LocalConfig struct {
	// RootDir is the base directory on the host filesystem.
	RootDir string
	// BaseURL is the URL prefix used for generating public links (e.g., "/uploads").
	BaseURL string
	// ShardDepth specifies subdirectory nesting depth (e.g., 2 -> "ab/cd/abcdef..."). Default: 2.
	ShardDepth int
	// FileMode specifies file permissions (default: 0600).
	FileMode os.FileMode
	// DirMode specifies directory permissions (default: 0700).
	DirMode os.FileMode
}

// LocalStorage persists files onto the local filesystem with sandboxing and atomic writes.
type LocalStorage struct {
	cfg LocalConfig
}

// NewLocalStorage creates a sandboxed local filesystem storage driver.
func NewLocalStorage(rootDir string) (*LocalStorage, error) {
	return NewLocalStorageWithConfig(LocalConfig{RootDir: rootDir})
}

// NewLocalStorageWithConfig initializes LocalStorage with custom configuration.
func NewLocalStorageWithConfig(cfg LocalConfig) (*LocalStorage, error) {
	if cfg.RootDir == "" {
		return nil, errors.New("storage: root directory cannot be empty")
	}

	absRoot, err := filepath.Abs(filepath.Clean(cfg.RootDir))
	if err != nil {
		return nil, fmt.Errorf("storage: invalid root directory: %w", err)
	}
	cfg.RootDir = absRoot

	if cfg.ShardDepth < 0 {
		cfg.ShardDepth = 0
	}
	if cfg.FileMode == 0 {
		cfg.FileMode = 0600
	}
	if cfg.DirMode == 0 {
		cfg.DirMode = 0700
	}

	if err := os.MkdirAll(cfg.RootDir, cfg.DirMode); err != nil {
		return nil, fmt.Errorf("storage: failed to create root directory: %w", err)
	}

	return &LocalStorage{cfg: cfg}, nil
}

// Save writes data to disk atomically with directory sharding.
func (s *LocalStorage) Save(ctx context.Context, key string, r io.Reader, size int64, opts SaveOptions) (*FileRecord, error) {
	targetPath, err := s.resolvePath(key)
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, s.cfg.DirMode); err != nil {
		return nil, fmt.Errorf("storage: failed to create directory: %w", err)
	}

	// Atomic write using unique temp file
	tmpPath := fmt.Sprintf("%s.tmp.%s", targetPath, randomSuffix(8))
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, s.cfg.FileMode)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to open temp file: %w", err)
	}

	written, err := io.Copy(f, r)
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("storage: write failed: %w", err)
	}

	_ = f.Sync()
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("storage: close temp file failed: %w", err)
	}

	// Rename temp file to final target
	if err := os.Rename(tmpPath, targetPath); err != nil {
		_ = os.Remove(tmpPath)
		return nil, fmt.Errorf("storage: atomic rename failed: %w", err)
	}

	record := &FileRecord{
		Key:          key,
		OriginalName: opts.OriginalName,
		Size:         written,
		MIME:         opts.MIME,
		Extension:    opts.Extension,
		SHA256:       opts.SHA256,
		Metadata:     opts.Metadata,
		CreatedAt:    time.Now().UTC(),
	}

	// Write sidecar metadata
	s.writeMeta(key, record)

	return record, nil
}

// Open returns a seekable file handle for reading.
func (s *LocalStorage) Open(ctx context.Context, key string) (ReadSeekCloser, *FileRecord, error) {
	targetPath, err := s.resolvePath(key)
	if err != nil {
		return nil, nil, err
	}

	f, err := os.Open(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrFileNotFound
		}
		return nil, nil, err
	}

	record, err := s.Stat(ctx, key)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}

	return f, record, nil
}

// Delete removes the target file and its metadata sidecar.
func (s *LocalStorage) Delete(ctx context.Context, key string) error {
	targetPath, err := s.resolvePath(key)
	if err != nil {
		return err
	}

	metaPath := targetPath + ".meta.json"
	_ = os.Remove(metaPath)

	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

// Exists checks if the key exists on disk.
func (s *LocalStorage) Exists(ctx context.Context, key string) (bool, error) {
	targetPath, err := s.resolvePath(key)
	if err != nil {
		return false, err
	}

	_, err = os.Stat(targetPath)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// Stat retrieves metadata about the stored file.
func (s *LocalStorage) Stat(ctx context.Context, key string) (*FileRecord, error) {
	targetPath, err := s.resolvePath(key)
	if err != nil {
		return nil, err
	}

	// Try reading metadata sidecar first
	metaPath := targetPath + ".meta.json"
	if data, err := os.ReadFile(metaPath); err == nil {
		var rec FileRecord
		if json.Unmarshal(data, &rec) == nil {
			return &rec, nil
		}
	}

	// Fallback to inspecting os.FileInfo
	fi, err := os.Stat(targetPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrFileNotFound
		}
		return nil, err
	}

	return &FileRecord{
		Key:       key,
		Size:      fi.Size(),
		Extension: filepath.Ext(key),
		CreatedAt: fi.ModTime().UTC(),
	}, nil
}

// URL generates the public URL for accessing the file.
func (s *LocalStorage) URL(ctx context.Context, key string, opts URLOptions) (string, error) {
	base := strings.TrimRight(s.cfg.BaseURL, "/")
	if base == "" {
		base = "/files"
	}
	url := fmt.Sprintf("%s/%s", base, key)
	if opts.Download {
		url += "?download=true"
		if opts.Filename != "" {
			url += "&filename=" + opts.Filename
		}
	}
	return url, nil
}

func (s *LocalStorage) writeMeta(key string, record *FileRecord) {
	targetPath, err := s.resolvePath(key)
	if err != nil {
		return
	}
	data, err := json.Marshal(record)
	if err != nil {
		return
	}
	_ = os.WriteFile(targetPath+".meta.json", data, s.cfg.FileMode)
}

func (s *LocalStorage) resolvePath(key string) (string, error) {
	cleanKey := filepath.Clean(filepath.ToSlash(key))
	cleanKey = strings.TrimLeft(cleanKey, "/")

	// Check path traversal
	if strings.HasPrefix(cleanKey, "..") || strings.Contains(cleanKey, "/../") {
		return "", ErrPathTraversal
	}

	var subDirs string
	baseName := filepath.Base(cleanKey)
	if s.cfg.ShardDepth > 0 && len(baseName) >= s.cfg.ShardDepth*2 {
		parts := make([]string, 0, s.cfg.ShardDepth)
		for i := 0; i < s.cfg.ShardDepth; i++ {
			parts = append(parts, baseName[i*2:i*2+2])
		}
		subDirs = filepath.Join(parts...)
	}

	fullPath := filepath.Join(s.cfg.RootDir, subDirs, cleanKey)
	absPath, err := filepath.Abs(fullPath)
	if err != nil {
		return "", err
	}

	// Verify that the path is strictly inside RootDir
	rel, err := filepath.Rel(s.cfg.RootDir, absPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return "", ErrPathTraversal
	}

	return absPath, nil
}

func randomSuffix(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
