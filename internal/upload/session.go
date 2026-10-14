package upload

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Session struct {
	Mu           sync.Mutex
	ID           string
	OwnerID      int
	FolderID     string
	Filename     string
	MimeType     string
	ExpectedSize int64
	UploadedSize int64
	TempFilePath  string
	PlaintextHash string
	StartedAt     time.Time
	LastActiveAt time.Time
}

type SessionMetadata struct {
	ID            string    `json:"id"`
	OwnerID       int       `json:"owner_id"`
	FolderID      string    `json:"folder_id"`
	Filename      string    `json:"filename"`
	MimeType      string    `json:"mime_type"`
	ExpectedSize  int64     `json:"expected_size"`
	UploadedSize  int64     `json:"uploaded_size"`
	TempFilePath  string    `json:"temp_file_path"`
	PlaintextHash string    `json:"plaintext_hash"`
	StartedAt     time.Time `json:"started_at"`
	LastActiveAt  time.Time `json:"last_active_at"`
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	TempDir  string
}

func (sm *SessionManager) metaPath(id string) string {
	return filepath.Join(sm.TempDir, fmt.Sprintf("upload_%s.meta.json", id))
}

func (sm *SessionManager) PersistSession(sess *Session) error {
	meta := SessionMetadata{
		ID:            sess.ID,
		OwnerID:       sess.OwnerID,
		FolderID:      sess.FolderID,
		Filename:      sess.Filename,
		MimeType:      sess.MimeType,
		ExpectedSize:  sess.ExpectedSize,
		UploadedSize:  sess.UploadedSize,
		TempFilePath:  sess.TempFilePath,
		PlaintextHash: sess.PlaintextHash,
		StartedAt:     sess.StartedAt,
		LastActiveAt:  sess.LastActiveAt,
	}

	data, err := json.Marshal(meta)
	if err != nil {
		return err
	}

	return os.WriteFile(sm.metaPath(sess.ID), data, 0600)
}

func NewSessionManager(tempDir string) (*SessionManager, error) {
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return nil, err
	}
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		TempDir:  tempDir,
	}

	// Restore active sessions from disk metadata so half-uploaded files survive server restarts
	entries, err := os.ReadDir(tempDir)
	if err == nil {
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), "upload_") || !strings.HasSuffix(entry.Name(), ".meta.json") {
				continue
			}
			metaPath := filepath.Join(tempDir, entry.Name())
			data, err := os.ReadFile(metaPath)
			if err != nil {
				continue
			}
			var meta SessionMetadata
			if err := json.Unmarshal(data, &meta); err != nil {
				continue
			}
			// Verify that the corresponding temp file exists on disk
			if _, err := os.Stat(meta.TempFilePath); err == nil && meta.ID != "" {
				sm.sessions[meta.ID] = &Session{
					ID:            meta.ID,
					OwnerID:       meta.OwnerID,
					FolderID:      meta.FolderID,
					Filename:      meta.Filename,
					MimeType:      meta.MimeType,
					ExpectedSize:  meta.ExpectedSize,
					UploadedSize:  meta.UploadedSize,
					TempFilePath:  meta.TempFilePath,
					PlaintextHash: meta.PlaintextHash,
					StartedAt:     meta.StartedAt,
					LastActiveAt:  meta.LastActiveAt,
				}
			} else {
				_ = os.Remove(metaPath)
			}
		}
	}

	return sm, nil
}

func GenerateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (sm *SessionManager) CreateSession(ownerID int, folderID, filename, mimeType string, size int64) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := GenerateID()
	tempPath := filepath.Join(sm.TempDir, fmt.Sprintf("upload_%s.tmp", id))

	// Pre-allocate or create empty temp file
	f, err := os.Create(tempPath)
	if err != nil {
		return nil, err
	}
	f.Close()

	sess := &Session{
		ID:           id,
		OwnerID:      ownerID,
		FolderID:     folderID,
		Filename:     filename,
		MimeType:     mimeType,
		ExpectedSize: size,
		UploadedSize: 0,
		TempFilePath: tempPath,
		StartedAt:    time.Now(),
		LastActiveAt: time.Now(),
	}

	sm.sessions[id] = sess
	_ = sm.PersistSession(sess)
	return sess, nil
}

func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessions[id]
	return sess, ok
}

// FindActiveSession searches for an existing unfinished session matching the given criteria.
func (sm *SessionManager) FindActiveSession(ownerID int, folderID, filename string, size int64) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, sess := range sm.sessions {
		if sess.OwnerID == ownerID &&
			sess.FolderID == folderID &&
			sess.Filename == filename &&
			sess.ExpectedSize == size &&
			sess.UploadedSize < sess.ExpectedSize {
			// Verify that the physical temp file actually exists
			if _, err := os.Stat(sess.TempFilePath); err == nil {
				return sess, true
			}
		}
	}
	return nil, false
}

func (sm *SessionManager) DeleteSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if sess, ok := sm.sessions[id]; ok {
		_ = os.Remove(sess.TempFilePath)
		_ = os.Remove(sm.metaPath(id))
	}
	delete(sm.sessions, id)
}

// CleanupStaleSessions removes expired sessions and unlinks abandoned temporary and metadata files.
func (sm *SessionManager) CleanupStaleSessions(maxAge time.Duration) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for id, sess := range sm.sessions {
		if now.Sub(sess.LastActiveAt) > maxAge {
			_ = os.Remove(sess.TempFilePath)
			_ = os.Remove(sm.metaPath(id))
			delete(sm.sessions, id)
			cleaned++
		}
	}
	return cleaned
}

// PurgeAll removes all active upload sessions and unlinks all temporary and metadata files immediately.
func (sm *SessionManager) PurgeAll() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cleaned := 0
	for id, sess := range sm.sessions {
		_ = os.Remove(sess.TempFilePath)
		_ = os.Remove(sm.metaPath(id))
		delete(sm.sessions, id)
		cleaned++
	}

	// Safety scan to remove any orphaned .tmp or .meta.json files in TempDir
	if entries, err := os.ReadDir(sm.TempDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && (strings.HasPrefix(e.Name(), "upload_") && (strings.HasSuffix(e.Name(), ".tmp") || strings.HasSuffix(e.Name(), ".meta.json"))) {
				_ = os.Remove(filepath.Join(sm.TempDir, e.Name()))
			}
		}
	}

	return cleaned
}
