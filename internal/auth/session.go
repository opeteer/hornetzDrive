package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/internal/crypto"
)


// SessionStore holds RAM-only Vault Keys mapped by a volatile Session ID.
// If the server restarts, or a panic purge is triggered, these keys are irrevocably lost.
type sessionEntry struct {
	key       []byte
	expiresAt time.Time
}

type SessionStore struct {
	mu        sync.RWMutex
	vaultKeys map[string]sessionEntry
}

var GlobalSessionStore = &SessionStore{
	vaultKeys: make(map[string]sessionEntry),
}

// SetKey stores the Vault Key in RAM with a 24-hour expiration.
func (s *SessionStore) SetKey(sessionID string, vk []byte) {
	s.SetKeyWithTTL(sessionID, vk, 24*time.Hour)
}

// SetKeyWithTTL stores the Vault Key in RAM with a specific TTL.
func (s *SessionStore) SetKeyWithTTL(sessionID string, vk []byte, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vaultKeys[sessionID] = sessionEntry{
		key:       vk,
		expiresAt: time.Now().Add(ttl),
	}
}

// GetKey retrieves the Vault Key from RAM if not expired.
func (s *SessionStore) GetKey(sessionID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.vaultKeys[sessionID]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.key, true
}

// DeleteKey removes a specific Vault Key from RAM.
func (s *SessionStore) DeleteKey(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.vaultKeys[sessionID]; ok {
		rand.Read(entry.key)
		delete(s.vaultKeys, sessionID)
	}
}

// HasKey checks if a non-expired Vault Key exists in RAM for the session.
func (s *SessionStore) HasKey(sessionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.vaultKeys[sessionID]
	if !ok || time.Now().After(entry.expiresAt) {
		return false
	}
	return true
}

// CleanupStaleKeys removes expired session keys from RAM.
func (s *SessionStore) CleanupStaleKeys() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cleaned := 0
	for id, entry := range s.vaultKeys {
		if now.After(entry.expiresAt) {
			rand.Read(entry.key)
			delete(s.vaultKeys, id)
			cleaned++
		}
	}
	return cleaned
}

// Purge completely obliterates all Vault Keys from RAM.
func (s *SessionStore) Purge() {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Overwrite existing keys with random bytes before deletion to prevent memory forensics
	for k, entry := range s.vaultKeys {
		rand.Read(entry.key)
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

type LoginRequest struct {
	Password string `json:"password" form:"password"`
}

var (
	defaultVaultSalt = []byte("hornetz_vault_master_salt_32b_!")
	defaultVaultHash = crypto.DeriveMEK([]byte("ManusiaIdaman"), defaultVaultSalt)
)

// VerifyMasterPassword validates password using Argon2id constant-time comparison against master key
func VerifyMasterPassword(password string) bool {
	if password == "" {
		return false
	}
	return crypto.VerifyPassword([]byte(password), defaultVaultSalt, defaultVaultHash)
}

// LoginMock simulates unlocking the vault and storing the VK in RAM using Argon2id.
func LoginMock(c *echo.Context) error {
	var req LoginRequest
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "Invalid request"})
	}

	// Validate the password using Argon2id constant-time comparison
	if !crypto.VerifyPassword([]byte(req.Password), defaultVaultSalt, defaultVaultHash) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "Invalid master password"})
	}

	sessBytes := make([]byte, 16)
	_, _ = rand.Read(sessBytes)
	sessionID := "sess_" + hex.EncodeToString(sessBytes)
	vk := crypto.DeriveMEK([]byte(req.Password), defaultVaultSalt)

	GlobalSessionStore.SetKey(sessionID, vk)

	c.SetCookie(&http.Cookie{
		Name:     "swarm_session",
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(24 * time.Hour),
	})

	return c.JSON(http.StatusOK, map[string]string{
		"message":    "Vault Unlocked. VK in RAM.",
		"session_id": sessionID,
	})
}

// LockVault terminates the current active Vault session and obliterates its key from RAM.
func LockVault(c *echo.Context) error {
	cookie, err := c.Cookie("swarm_session")
	if err == nil && cookie != nil {
		GlobalSessionStore.DeleteKey(cookie.Value)
	}

	c.SetCookie(&http.Cookie{
		Name:     "swarm_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	return c.JSON(http.StatusOK, map[string]string{
		"status":  "locked",
		"message": "Vault locked and session destroyed from RAM.",
	})
}
