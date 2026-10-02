package filetest

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"ztatic-go-framework/upload/storage"
)

// SaveCallRecord records parameters passed to Save.
type SaveCallRecord struct {
	Key       string
	Content   []byte
	Size      int64
	Opts      storage.SaveOptions
	Timestamp time.Time
}

// URLCallRecord records parameters passed to URL.
type URLCallRecord struct {
	Key       string
	Opts      storage.URLOptions
	Timestamp time.Time
}

// mockReadSeekCloser wraps *bytes.Reader to satisfy storage.ReadSeekCloser.
type mockReadSeekCloser struct {
	*bytes.Reader
}

func (m *mockReadSeekCloser) Close() error { return nil }

// MockStorage is an enterprise-grade thread-safe test double for storage.Storage,
// offering detailed interaction spies and deterministic fault injection.
type MockStorage struct {
	mu      sync.RWMutex
	data    map[string][]byte
	records map[string]*storage.FileRecord

	// Interaction Spies
	saveCalls   []SaveCallRecord
	deleteCalls []string
	openCalls   []string
	existsCalls []string
	statCalls   []string
	urlCalls    []URLCallRecord

	// Fault Injection & Stubs
	failSaveErr    error
	failSaveKeys   map[string]error
	failOpenErr    error
	failOpenKeys   map[string]error
	failDeleteErr  error
	failDeleteKeys map[string]error
	failExistsErr  error
	failStatErr    error
	failURLErr     error
	latency        time.Duration
	customURLFunc  func(key string, opts storage.URLOptions) (string, error)
}

// NewMockStorage instantiates an empty, clean MockStorage.
func NewMockStorage() *MockStorage {
	return &MockStorage{
		data:           make(map[string][]byte),
		records:        make(map[string]*storage.FileRecord),
		failSaveKeys:   make(map[string]error),
		failOpenKeys:   make(map[string]error),
		failDeleteKeys: make(map[string]error),
	}
}

// Save persists the stream in-memory and records the invocation spy.
func (m *MockStorage) Save(ctx context.Context, key string, r io.Reader, size int64, opts storage.SaveOptions) (*storage.FileRecord, error) {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Fault injection checks
	if err, ok := m.failSaveKeys[key]; ok && err != nil {
		return nil, err
	}
	if m.failSaveErr != nil {
		return nil, m.failSaveErr
	}

	buf, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("mockstorage: read stream failed: %w", err)
	}

	call := SaveCallRecord{
		Key:       key,
		Content:   buf,
		Size:      int64(len(buf)),
		Opts:      opts,
		Timestamp: time.Now().UTC(),
	}
	m.saveCalls = append(m.saveCalls, call)

	record := &storage.FileRecord{
		Key:          key,
		OriginalName: opts.OriginalName,
		Size:         int64(len(buf)),
		MIME:         opts.MIME,
		Extension:    opts.Extension,
		SHA256:       opts.SHA256,
		Metadata:     opts.Metadata,
		CreatedAt:    call.Timestamp,
	}

	m.data[key] = buf
	m.records[key] = record

	return record, nil
}

// Open retrieves a readable and seekable stream from memory.
func (m *MockStorage) Open(ctx context.Context, key string) (storage.ReadSeekCloser, *storage.FileRecord, error) {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}

	m.mu.Lock()
	m.openCalls = append(m.openCalls, key)
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if err, ok := m.failOpenKeys[key]; ok && err != nil {
		return nil, nil, err
	}
	if m.failOpenErr != nil {
		return nil, nil, m.failOpenErr
	}

	buf, ok := m.data[key]
	if !ok {
		return nil, nil, storage.ErrFileNotFound
	}

	record := m.records[key]
	return &mockReadSeekCloser{Reader: bytes.NewReader(buf)}, record, nil
}

// Delete removes the file from memory.
func (m *MockStorage) Delete(ctx context.Context, key string) error {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.deleteCalls = append(m.deleteCalls, key)

	if err, ok := m.failDeleteKeys[key]; ok && err != nil {
		return err
	}
	if m.failDeleteErr != nil {
		return m.failDeleteErr
	}

	delete(m.data, key)
	delete(m.records, key)
	return nil
}

// Exists checks if the key exists in memory.
func (m *MockStorage) Exists(ctx context.Context, key string) (bool, error) {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}

	m.mu.Lock()
	m.existsCalls = append(m.existsCalls, key)
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.failExistsErr != nil {
		return false, m.failExistsErr
	}

	_, ok := m.data[key]
	return ok, nil
}

// Stat retrieves metadata about the file.
func (m *MockStorage) Stat(ctx context.Context, key string) (*storage.FileRecord, error) {
	if m.latency > 0 {
		time.Sleep(m.latency)
	}

	m.mu.Lock()
	m.statCalls = append(m.statCalls, key)
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.failStatErr != nil {
		return nil, m.failStatErr
	}

	rec, ok := m.records[key]
	if !ok {
		return nil, storage.ErrFileNotFound
	}
	return rec, nil
}

// URL generates a file URL.
func (m *MockStorage) URL(ctx context.Context, key string, opts storage.URLOptions) (string, error) {
	m.mu.Lock()
	m.urlCalls = append(m.urlCalls, URLCallRecord{Key: key, Opts: opts, Timestamp: time.Now().UTC()})
	m.mu.Unlock()

	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.failURLErr != nil {
		return "", m.failURLErr
	}

	if m.customURLFunc != nil {
		return m.customURLFunc(key, opts)
	}

	return fmt.Sprintf("/files/%s", key), nil
}

// -----------------------------------------------------------------------------
// Spy & Inspection API
// -----------------------------------------------------------------------------

// WasSaved returns true if Save was called for the given key.
func (m *MockStorage) WasSaved(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, call := range m.saveCalls {
		if call.Key == key {
			return true
		}
	}
	return false
}

// WasDeleted returns true if Delete was called for the given key.
func (m *MockStorage) WasDeleted(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range m.deleteCalls {
		if k == key {
			return true
		}
	}
	return false
}

// WasOpened returns true if Open was called for the given key.
func (m *MockStorage) WasOpened(key string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, k := range m.openCalls {
		if k == key {
			return true
		}
	}
	return false
}

// SaveCallCount returns total number of Save invocations.
func (m *MockStorage) SaveCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.saveCalls)
}

// DeleteCallCount returns total number of Delete invocations.
func (m *MockStorage) DeleteCallCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.deleteCalls)
}

// SaveCalls returns a copy of all recorded Save calls.
func (m *MockStorage) SaveCalls() []SaveCallRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]SaveCallRecord, len(m.saveCalls))
	copy(copied, m.saveCalls)
	return copied
}

// DeleteCalls returns a list of keys passed to Delete.
func (m *MockStorage) DeleteCalls() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]string, len(m.deleteCalls))
	copy(copied, m.deleteCalls)
	return copied
}

// LastSaveCall returns the most recent Save invocation, or nil.
func (m *MockStorage) LastSaveCall() *SaveCallRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.saveCalls) == 0 {
		return nil
	}
	c := m.saveCalls[len(m.saveCalls)-1]
	return &c
}

// StoredKeys returns all currently stored file keys.
func (m *MockStorage) StoredKeys() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	keys := make([]string, 0, len(m.data))
	for k := range m.data {
		keys = append(keys, k)
	}
	return keys
}

// StoredCount returns the number of active stored files.
func (m *MockStorage) StoredCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.data)
}

// GetStoredBytes returns the stored byte slice for key, if present.
func (m *MockStorage) GetStoredBytes(key string) ([]byte, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	buf, ok := m.data[key]
	if !ok {
		return nil, false
	}
	copied := make([]byte, len(buf))
	copy(copied, buf)
	return copied, true
}

// GetRecord returns the stored FileRecord for key, if present.
func (m *MockStorage) GetRecord(key string) (*storage.FileRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.records[key]
	return rec, ok
}

// -----------------------------------------------------------------------------
// Fault Injection & Stubbing API
// -----------------------------------------------------------------------------

// FailSave causes all subsequent Save calls to return err.
func (m *MockStorage) FailSave(err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failSaveErr = err
	return m
}

// FailSaveForKey causes Save for the specific key to return err.
func (m *MockStorage) FailSaveForKey(key string, err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failSaveKeys[key] = err
	return m
}

// FailOpen causes all subsequent Open calls to return err.
func (m *MockStorage) FailOpen(err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failOpenErr = err
	return m
}

// FailOpenForKey causes Open for the specific key to return err.
func (m *MockStorage) FailOpenForKey(key string, err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failOpenKeys[key] = err
	return m
}

// FailDelete causes all subsequent Delete calls to return err.
func (m *MockStorage) FailDelete(err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failDeleteErr = err
	return m
}

// FailDeleteForKey causes Delete for the specific key to return err.
func (m *MockStorage) FailDeleteForKey(key string, err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failDeleteKeys[key] = err
	return m
}

// FailExists causes Exists to return err.
func (m *MockStorage) FailExists(err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failExistsErr = err
	return m
}

// FailStat causes Stat to return err.
func (m *MockStorage) FailStat(err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failStatErr = err
	return m
}

// FailURL causes URL generation to return err.
func (m *MockStorage) FailURL(err error) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failURLErr = err
	return m
}

// SimulateDiskFull injects an OS ENOSPC "no space left on device" error into Save.
func (m *MockStorage) SimulateDiskFull() *MockStorage {
	return m.FailSave(fmt.Errorf("write storage: no space left on device"))
}

// SimulatePermissionDenied injects an os.ErrPermission error into Save.
func (m *MockStorage) SimulatePermissionDenied() *MockStorage {
	return m.FailSave(os.ErrPermission)
}

// SimulateLatency injects an artificial delay on storage operations.
func (m *MockStorage) SimulateLatency(d time.Duration) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.latency = d
	return m
}

// SetCustomURL sets a custom URL generation callback.
func (m *MockStorage) SetCustomURL(fn func(key string, opts storage.URLOptions) (string, error)) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.customURLFunc = fn
	return m
}

// SeedFile stores a pre-existing file directly in mock memory, bypassing spies and stubs.
// Useful for seeding state before running download or deletion tests.
func (m *MockStorage) SeedFile(key string, content []byte, mimeType string) *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()

	copied := make([]byte, len(content))
	copy(copied, content)

	m.data[key] = copied
	m.records[key] = &storage.FileRecord{
		Key:          key,
		OriginalName: key,
		Size:         int64(len(content)),
		MIME:         mimeType,
		CreatedAt:    time.Now().UTC(),
	}
	return m
}

// Reset clears all stored files, recorded interaction spies, and injected error stubs.
func (m *MockStorage) Reset() *MockStorage {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string][]byte)
	m.records = make(map[string]*storage.FileRecord)
	m.saveCalls = nil
	m.deleteCalls = nil
	m.openCalls = nil
	m.existsCalls = nil
	m.statCalls = nil
	m.urlCalls = nil
	m.failSaveErr = nil
	m.failSaveKeys = make(map[string]error)
	m.failOpenErr = nil
	m.failOpenKeys = make(map[string]error)
	m.failDeleteErr = nil
	m.failDeleteKeys = make(map[string]error)
	m.failExistsErr = nil
	m.failStatErr = nil
	m.failURLErr = nil
	m.latency = 0
	m.customURLFunc = nil
	return m
}
