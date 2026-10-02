package session

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strconv"
	"sync"
	"time"
)

// Session represents an active HTTP session with state tracking,
// flash messaging, and session fixation defense.
type Session struct {
	ID          string           `json:"id"`
	Values      map[string]any   `json:"values"`
	CreatedAt   time.Time        `json:"created_at"`
	AccessedAt  time.Time        `json:"accessed_at"`
	ExpiresAt   time.Time        `json:"expires_at"`
	FlashesMap  map[string][]any `json:"flashes,omitempty"`

	oldID       string
	isNew       bool
	isModified  bool
	isDestroyed bool
	mu          sync.RWMutex
}

// NewSession creates an empty session initialized with 256 bits of cryptographic entropy.
func NewSession(idleTimeout time.Duration) *Session {
	now := time.Now()
	id, _ := GenerateSessionID()
	return &Session{
		ID:          id,
		Values:      make(map[string]any),
		CreatedAt:   now,
		AccessedAt:  now,
		ExpiresAt:   now.Add(idleTimeout),
		FlashesMap:  make(map[string][]any),
		isNew:       true,
		isModified:  false,
		isDestroyed: false,
	}
}

// GenerateSessionID generates a cryptographically secure 32-byte (256-bit) session identifier.
func GenerateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// RegenerateID prevents Session Fixation by creating a new unique session identifier
// while preserving existing values and flags (OWASP Session Management).
func (s *Session) RegenerateID() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	newID, err := GenerateSessionID()
	if err != nil {
		return err
	}
	if s.oldID == "" {
		s.oldID = s.ID
	}
	s.ID = newID
	s.isModified = true
	s.isNew = true
	return nil
}

// OldID returns the previous session ID if RegenerateID was called, or empty.
func (s *Session) OldID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.oldID
}

// Get returns the value associated with key, or nil.
func (s *Session) Get(key string) any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Values[key]
}

// GetString returns the value associated with key as a string.
func (s *Session) GetString(key string) string {
	val := s.Get(key)
	if val == nil {
		return ""
	}
	if str, ok := val.(string); ok {
		return str
	}
	return ""
}

// GetInt returns the value associated with key as an int.
func (s *Session) GetInt(key string) int {
	val := s.Get(key)
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		i, _ := strconv.Atoi(v)
		return i
	default:
		return 0
	}
}

// GetBool returns the value associated with key as a boolean.
func (s *Session) GetBool(key string) bool {
	val := s.Get(key)
	if val == nil {
		return false
	}
	if b, ok := val.(bool); ok {
		return b
	}
	return false
}

// Set stores a key-value pair and marks the session as modified.
func (s *Session) Set(key string, val any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Values[key] = val
	s.isModified = true
}

// Delete removes a key and marks the session as modified.
func (s *Session) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.Values[key]; ok {
		delete(s.Values, key)
		s.isModified = true
	}
}

// Clear removes all stored values.
func (s *Session) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Values = make(map[string]any)
	s.isModified = true
}

// Destroy marks the session for immediate deletion from store and cookie removal.
func (s *Session) Destroy() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.isDestroyed = true
	s.isModified = true
}

// Flash stores a one-time message under the given key (e.g. for HTML redirects).
func (s *Session) Flash(key string, val any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FlashesMap == nil {
		s.FlashesMap = make(map[string][]any)
	}
	s.FlashesMap[key] = append(s.FlashesMap[key], val)
	s.isModified = true
}

// Flashes retrieves and immediately clears all one-time messages stored under key.
func (s *Session) Flashes(key string) []any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.FlashesMap == nil {
		return nil
	}
	flashes, ok := s.FlashesMap[key]
	if !ok {
		return nil
	}
	delete(s.FlashesMap, key)
	s.isModified = true
	return flashes
}

// Touch refreshes the access timestamp and extends the expiration.
func (s *Session) Touch(idleTimeout time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.AccessedAt = now
	s.ExpiresAt = now.Add(idleTimeout)
}

// IsNew returns true if this session was newly created during the current request.
func (s *Session) IsNew() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isNew
}

// IsModified returns true if any value or flash was changed.
func (s *Session) IsModified() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isModified
}

// IsDestroyed returns true if the session was marked for destruction.
func (s *Session) IsDestroyed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.isDestroyed
}
