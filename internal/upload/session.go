package upload

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Session struct {
	ID           string
	OwnerID      int
	FolderID     string
	Filename     string
	MimeType     string
	ExpectedSize int64
	UploadedSize int64
	TempFilePath string
	StartedAt    time.Time
	LastActiveAt time.Time
}

type SessionManager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	TempDir  string
}

func NewSessionManager(tempDir string) (*SessionManager, error) {
	if err := os.MkdirAll(tempDir, 0700); err != nil {
		return nil, err
	}
	return &SessionManager{
		sessions: make(map[string]*Session),
		TempDir:  tempDir,
	}, nil
}

func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (sm *SessionManager) CreateSession(ownerID int, folderID, filename, mimeType string, size int64) (*Session, error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	id := generateID()
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
	return sess, nil
}

func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	sess, ok := sm.sessions[id]
	return sess, ok
}

func (sm *SessionManager) DeleteSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, id)
}
