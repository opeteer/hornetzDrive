package auth

import (
	"crypto/rand"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/internal/crypto"
)

// SessionStore holds RAM-only Vault Keys mapped by a volatile Session ID.
// If the server restarts, or a panic purge is triggered, these keys are irrevocably lost.
type SessionStore struct {
	mu        sync.RWMutex
	vaultKeys map[string][]byte
}

var GlobalSessionStore = &SessionStore{
	vaultKeys: make(map[string][]byte),
}

// SetKey stores the Vault Key in RAM.
func (s *SessionStore) SetKey(sessionID string, vk []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vaultKeys[sessionID] = vk
}

// GetKey retrieves the Vault Key from RAM.
func (s *SessionStore) GetKey(sessionID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	vk, ok := s.vaultKeys[sessionID]
	return vk, ok
}

// Purge completely obliterates all Vault Keys from RAM.
func (s *SessionStore) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Overwrite existing keys with random bytes before deletion to prevent memory forensics
	for k, vk := range s.vaultKeys {
		rand.Read(vk)
		delete(s.vaultKeys, k)
	}
}

// Middleware injects the Vault Key into the request context if a valid session exists.
func VaultKeyMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			// In a real app, read sessionID from secure HttpOnly cookie
			cookie, err := c.Cookie("swarm_session")
			if err == nil {
				vk, exists := GlobalSessionStore.GetKey(cookie.Value)
				if exists {
					c.Set("vault_key", vk)
					return next(c)
				}
			}

			// Fallback to dummy key for testing during development if no cookie exists or session not in RAM
			c.Set("vault_key", crypto.DummyVK())
			return next(c)
		}
	}
}

// LoginMock simulates unlocking the vault and storing the VK in RAM.
func LoginMock(c *echo.Context) error {
	sessionID := "mock-session-12345"
	vk := crypto.DummyVK() // Derived using Argon2id in a full implementation

	GlobalSessionStore.SetKey(sessionID, vk)

	c.SetCookie(&http.Cookie{
		Name:     "swarm_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	return c.JSON(http.StatusOK, "Vault Unlocked. VK in RAM.")
}
