package storage

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"sync"
	"time"
)

// MemoryStorage is a thread-safe in-memory storage driver, ideal for unit testing.
type MemoryStorage struct {
	mu      sync.RWMutex
	data    map[string][]byte
	records map[string]*FileRecord
	baseURL string
}

// NewMemoryStorage creates an in-memory storage driver.
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		data:    make(map[string][]byte),
		records: make(map[string]*FileRecord),
		baseURL: "/files",
	}
}

// Save stores the payload in memory.
func (s *MemoryStorage) Save(ctx context.Context, key string, r io.Reader, size int64, opts SaveOptions) (*FileRecord, error) {
	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("storage: failed to read stream: %w", err)
	}

	record := &FileRecord{
		Key:          key,
		OriginalName: opts.OriginalName,
		Size:         int64(len(buf)),
		MIME:         opts.MIME,
		Extension:    opts.Extension,
		SHA256:       opts.SHA256,
		Metadata:     opts.Metadata,
		CreatedAt:    time.Now().UTC(),
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.data[key] = buf
	s.records[key] = record

	return record, nil
}

type memoryReadSeekCloser struct {
	*bytes.Reader
}

func (m *memoryReadSeekCloser) Close() error {
	return nil
}

// Open retrieves an in-memory seekable stream.
func (s *MemoryStorage) Open(ctx context.Context, key string) (ReadSeekCloser, *FileRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	buf, ok := s.data[key]
	if !ok {
		return nil, nil, ErrFileNotFound
	}

	record := s.records[key]
	return &memoryReadSeekCloser{Reader: bytes.NewReader(buf)}, record, nil
}

// Delete removes the file from memory.
func (s *MemoryStorage) Delete(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.data, key)
	delete(s.records, key)
	return nil
}

// Exists checks if the key is stored in memory.
func (s *MemoryStorage) Exists(ctx context.Context, key string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	_, ok := s.data[key]
	return ok, nil
}

// Stat returns metadata about the in-memory file.
func (s *MemoryStorage) Stat(ctx context.Context, key string) (*FileRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rec, ok := s.records[key]
	if !ok {
		return nil, ErrFileNotFound
	}
	return rec, nil
}

// URL generates a virtual link for the in-memory file.
func (s *MemoryStorage) URL(ctx context.Context, key string, opts URLOptions) (string, error) {
	return fmt.Sprintf("%s/%s", s.baseURL, key), nil
}
