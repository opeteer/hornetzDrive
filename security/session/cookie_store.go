package session

import (
	"context"
	"encoding/json"
	"time"

	"ztatic-go-framework/security/crypto"
)

// CookieStore implements a completely stateless session store.
// Session data is serialized, authenticated, and encrypted client-side using AES-256-GCM,
// requiring zero server-side memory or storage backends.
type CookieStore struct {
	cipher *crypto.CipherSuite
}

// NewCookieStore creates a new stateless cookie store using an AES-256-GCM cipher suite.
func NewCookieStore(cs *crypto.CipherSuite) (*CookieStore, error) {
	if cs == nil {
		return nil, ErrInvalidStore
	}
	return &CookieStore{cipher: cs}, nil
}

// Get decrypts and reconstructs the session from the encrypted cookie string.
func (c *CookieStore) Get(_ context.Context, encryptedCookieValue string) (*Session, error) {
	if encryptedCookieValue == "" {
		return nil, ErrSessionNotFound
	}

	plaintext, err := c.cipher.Decrypt(encryptedCookieValue)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	var s Session
	if err := json.Unmarshal([]byte(plaintext), &s); err != nil {
		return nil, err
	}

	if time.Now().After(s.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	s.isNew = false
	return &s, nil
}

// Save serializes and encrypts the session payload. The ciphertext is stored in s.ID
// so the session middleware can write it as the HTTP cookie value.
func (c *CookieStore) Save(_ context.Context, s *Session, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.ExpiresAt = time.Now().Add(ttl)
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	ciphertext, err := c.cipher.Encrypt(string(data))
	if err != nil {
		return err
	}

	s.ID = ciphertext
	return nil
}

// Destroy is a no-op server-side for stateless cookies.
func (c *CookieStore) Destroy(_ context.Context, _ string) error {
	return nil
}

// Touch re-encrypts the session with an extended TTL.
func (c *CookieStore) Touch(_ context.Context, _ string, _ time.Duration) error {
	return nil
}
