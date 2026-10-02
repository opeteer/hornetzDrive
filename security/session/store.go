package session

import (
	"context"
	"errors"
	"time"
)

var (
	ErrSessionNotFound = errors.New("ztatic/session: session not found")
	ErrSessionExpired  = errors.New("ztatic/session: session has expired")
	ErrInvalidStore    = errors.New("ztatic/session: invalid or uninitialized store")
)

// Store abstracts the persistence layer for sessions.
type Store interface {
	// Get retrieves a session by its ID. Returns ErrSessionNotFound if not present.
	Get(ctx context.Context, id string) (*Session, error)

	// Save writes or updates the session with the specified time-to-live.
	Save(ctx context.Context, s *Session, ttl time.Duration) error

	// Destroy removes the session immediately from storage.
	Destroy(ctx context.Context, id string) error

	// Touch extends the session's expiration time without modifying its payload.
	Touch(ctx context.Context, id string, ttl time.Duration) error
}
