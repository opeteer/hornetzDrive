package session

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is an in-memory thread-safe implementation of Store
// featuring automated background TTL cleanup.
type MemoryStore struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	stopCh   chan struct{}
}

// NewMemoryStore creates an in-memory session store with a default 1-minute cleanup interval.
func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithInterval(1 * time.Minute)
}

// NewMemoryStoreWithInterval creates an in-memory session store with a custom sweeper interval.
func NewMemoryStoreWithInterval(cleanupInterval time.Duration) *MemoryStore {
	store := &MemoryStore{
		sessions: make(map[string]*Session),
		stopCh:   make(chan struct{}),
	}

	if cleanupInterval > 0 {
		go store.cleanupLoop(cleanupInterval)
	}

	return store
}

// Get retrieves a session by ID.
func (m *MemoryStore) Get(_ context.Context, id string) (*Session, error) {
	m.mu.RLock()
	s, exists := m.sessions[id]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(s.ExpiresAt) {
		m.Destroy(context.Background(), id)
		return nil, ErrSessionExpired
	}

	// Create an isolated copy to prevent concurrent map access during request mutation
	s.mu.RLock()
	copiedValues := make(map[string]any, len(s.Values))
	for k, v := range s.Values {
		copiedValues[k] = v
	}
	copiedFlashes := make(map[string][]any, len(s.FlashesMap))
	for k, v := range s.FlashesMap {
		copiedFlashes[k] = append([]any{}, v...)
	}
	sessCopy := &Session{
		ID:         s.ID,
		Values:     copiedValues,
		CreatedAt:  s.CreatedAt,
		AccessedAt: s.AccessedAt,
		ExpiresAt:  s.ExpiresAt,
		FlashesMap: copiedFlashes,
		isNew:      false,
	}
	s.mu.RUnlock()

	return sessCopy, nil
}

// Save stores or updates a session.
func (m *MemoryStore) Save(_ context.Context, s *Session, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s.mu.RLock()
	copiedValues := make(map[string]any, len(s.Values))
	for k, v := range s.Values {
		copiedValues[k] = v
	}
	copiedFlashes := make(map[string][]any, len(s.FlashesMap))
	for k, v := range s.FlashesMap {
		copiedFlashes[k] = append([]any{}, v...)
	}
	stored := &Session{
		ID:         s.ID,
		Values:     copiedValues,
		CreatedAt:  s.CreatedAt,
		AccessedAt: s.AccessedAt,
		ExpiresAt:  time.Now().Add(ttl),
		FlashesMap: copiedFlashes,
		isNew:      false,
	}
	s.mu.RUnlock()

	m.sessions[s.ID] = stored
	return nil
}

// Destroy deletes a session from memory.
func (m *MemoryStore) Destroy(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
	return nil
}

// Touch refreshes the expiration time for the session.
func (m *MemoryStore) Touch(_ context.Context, id string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if s, exists := m.sessions[id]; exists {
		s.ExpiresAt = time.Now().Add(ttl)
		return nil
	}
	return ErrSessionNotFound
}

// Close terminates the background cleanup routine.
func (m *MemoryStore) Close() {
	select {
	case <-m.stopCh:
	default:
		close(m.stopCh)
	}
}

func (m *MemoryStore) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			m.mu.Lock()
			for id, sess := range m.sessions {
				if now.After(sess.ExpiresAt) {
					delete(m.sessions, id)
				}
			}
			m.mu.Unlock()
		}
	}
}
