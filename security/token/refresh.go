package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"sync"
	"time"
)

// TokenPair represents a combined access token and refresh token.
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"` // seconds until access token expires
	ExpiresAt    time.Time `json:"expires_at"`
}

// RefreshToken represents a stored refresh token entity.
type RefreshToken struct {
	ID        string    `json:"id"`        // SHA-256 hash of plaintext token
	FamilyID  string    `json:"family_id"` // Tracks token ancestry for rotation
	Subject   string    `json:"subject"`   // User/Actor ID
	Used      bool      `json:"used"`      // True once consumed
	ExpiresAt time.Time `json:"expires_at"`
}

// RefreshTokenStore abstracts persistence for refresh tokens and token families.
type RefreshTokenStore interface {
	Save(ctx context.Context, rt *RefreshToken) error
	Get(ctx context.Context, id string) (*RefreshToken, error)
	MarkUsed(ctx context.Context, id string) error
	RevokeFamily(ctx context.Context, familyID string) error
}

// MemoryRefreshTokenStore is a thread-safe in-memory store for refresh tokens.
type MemoryRefreshTokenStore struct {
	tokens   map[string]*RefreshToken
	families map[string]map[string]bool // familyID -> set of token IDs
	mu       sync.RWMutex
}

// NewMemoryRefreshTokenStore initializes an in-memory refresh token store.
func NewMemoryRefreshTokenStore() *MemoryRefreshTokenStore {
	return &MemoryRefreshTokenStore{
		tokens:   make(map[string]*RefreshToken),
		families: make(map[string]map[string]bool),
	}
}

// Save stores a new refresh token.
func (s *MemoryRefreshTokenStore) Save(_ context.Context, rt *RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tokens[rt.ID] = rt
	if s.families[rt.FamilyID] == nil {
		s.families[rt.FamilyID] = make(map[string]bool)
	}
	s.families[rt.FamilyID][rt.ID] = true
	return nil
}

// Get retrieves a refresh token by its hashed ID.
func (s *MemoryRefreshTokenStore) Get(_ context.Context, id string) (*RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rt, ok := s.tokens[id]
	if !ok {
		return nil, ErrInvalidToken
	}
	return rt, nil
}

// MarkUsed marks a refresh token as consumed.
func (s *MemoryRefreshTokenStore) MarkUsed(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rt, ok := s.tokens[id]; ok {
		rt.Used = true
		return nil
	}
	return ErrInvalidToken
}

// RevokeFamily revokes all tokens belonging to the specified family.
func (s *MemoryRefreshTokenStore) RevokeFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if ids, ok := s.families[familyID]; ok {
		for id := range ids {
			delete(s.tokens, id)
		}
		delete(s.families, familyID)
	}
	return nil
}

// GenerateRandomToken generates a cryptographically secure random string with 256 bits of entropy.
func GenerateRandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken returns the hex-encoded SHA-256 hash of a plaintext token.
func HashToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}
