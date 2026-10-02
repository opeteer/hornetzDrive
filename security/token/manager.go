package token

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"ztatic-go-framework/security/crypto"
)

// Engine abstracts the low-level signing and verification algorithm (JWT or Encrypted).
type Engine interface {
	Algorithm() Algorithm
	Sign(claims *Claims) (string, error)
	Verify(tokenString string) (*Token, error)
}

// Config defines configuration parameters for the Token Manager.
type Config struct {
	Algorithm    Algorithm
	SecretKey    []byte
	Cipher       *crypto.CipherSuite
	Issuer       string
	Audience     string
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	ClockSkew    time.Duration
	RefreshStore RefreshTokenStore
}

// DefaultConfig returns production-ready secure defaults for Token Manager.
func DefaultConfig(secretKey []byte) Config {
	return Config{
		Algorithm:    HS256,
		SecretKey:    secretKey,
		AccessTTL:    15 * time.Minute,
		RefreshTTL:   7 * 24 * time.Hour,
		ClockSkew:    1 * time.Minute,
		RefreshStore: NewMemoryRefreshTokenStore(),
	}
}

// Manager coordinates token generation, signature verification, claims validation,
// and refresh token rotation with reuse detection.
type Manager struct {
	cfg       Config
	engine    Engine
	blacklist map[string]time.Time // Revoked JTIs with expiry
	blackMu   sync.RWMutex
}

// NewManager initializes a Token Manager with the specified configuration.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = 15 * time.Minute
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = 7 * 24 * time.Hour
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 1 * time.Minute
	}
	if cfg.RefreshStore == nil {
		cfg.RefreshStore = NewMemoryRefreshTokenStore()
	}

	var engine Engine
	var err error

	if cfg.Cipher != nil {
		engine, err = NewEncryptedEngine(cfg.Cipher)
	} else {
		engine, err = NewHMACEngine(cfg.Algorithm, cfg.SecretKey)
	}
	if err != nil {
		return nil, err
	}

	return &Manager{
		cfg:       cfg,
		engine:    engine,
		blacklist: make(map[string]time.Time),
	}, nil
}

// Engine returns the underlying cryptographic engine.
func (m *Manager) Engine() Engine {
	return m.engine
}

// CreateAccessToken generates and signs a new access token for the given claims.
func (m *Manager) CreateAccessToken(claims *Claims) (string, error) {
	if claims == nil {
		claims = &Claims{}
	}

	now := time.Now()
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now.Unix()
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now.Add(m.cfg.AccessTTL).Unix()
	}
	if claims.Issuer == "" && m.cfg.Issuer != "" {
		claims.Issuer = m.cfg.Issuer
	}
	if claims.Audience == "" && m.cfg.Audience != "" {
		claims.Audience = m.cfg.Audience
	}
	if claims.ID == "" {
		// Generate cryptographically unique JTI
		jtiBytes := make([]byte, 16)
		_, _ = rand.Read(jtiBytes)
		claims.ID = hex.EncodeToString(jtiBytes)
	}

	return m.engine.Sign(claims)
}

// CreateTokenPair generates an access token and an accompanying single-use refresh token.
func (m *Manager) CreateTokenPair(ctx context.Context, claims *Claims) (*TokenPair, error) {
	if claims == nil {
		claims = &Claims{}
	}

	accessToken, err := m.CreateAccessToken(claims)
	if err != nil {
		return nil, err
	}

	plainRefreshToken, err := GenerateRandomToken()
	if err != nil {
		return nil, err
	}

	familyID, err := GenerateRandomToken()
	if err != nil {
		return nil, err
	}

	hashedID := HashToken(plainRefreshToken)
	expiresAt := time.Now().Add(m.cfg.RefreshTTL)

	rt := &RefreshToken{
		ID:        hashedID,
		FamilyID:  familyID,
		Subject:   claims.Subject,
		Used:      false,
		ExpiresAt: expiresAt,
	}

	if err := m.cfg.RefreshStore.Save(ctx, rt); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: plainRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(m.cfg.AccessTTL.Seconds()),
		ExpiresAt:    time.Now().Add(m.cfg.AccessTTL),
	}, nil
}

// RefreshTokens executes Refresh Token Rotation (RTR).
// It verifies the presented refresh token, checks for reuse (revoking the entire family
// if reuse is detected), and issues a new access token and rotated refresh token.
func (m *Manager) RefreshTokens(ctx context.Context, plainRefreshToken string, baseClaims *Claims) (*TokenPair, error) {
	hashedID := HashToken(plainRefreshToken)

	stored, err := m.cfg.RefreshStore.Get(ctx, hashedID)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Token Expiry Check
	if time.Now().After(stored.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	// Reuse Detection: If token was already marked used, attacker has replayed it!
	if stored.Used {
		// Invalidate the entire token family
		_ = m.cfg.RefreshStore.RevokeFamily(ctx, stored.FamilyID)
		return nil, ErrRefreshTokenReused
	}

	// Mark current refresh token as used
	if err := m.cfg.RefreshStore.MarkUsed(ctx, stored.ID); err != nil {
		return nil, err
	}

	// Construct claims for the new access token
	newClaims := &Claims{}
	if baseClaims != nil {
		*newClaims = *baseClaims
	}
	newClaims.Subject = stored.Subject

	newAccessToken, err := m.CreateAccessToken(newClaims)
	if err != nil {
		return nil, err
	}

	// Issue rotated refresh token under the same FamilyID
	newPlainRT, err := GenerateRandomToken()
	if err != nil {
		return nil, err
	}
	newHashedID := HashToken(newPlainRT)

	newRT := &RefreshToken{
		ID:        newHashedID,
		FamilyID:  stored.FamilyID,
		Subject:   stored.Subject,
		Used:      false,
		ExpiresAt: time.Now().Add(m.cfg.RefreshTTL),
	}

	if err := m.cfg.RefreshStore.Save(ctx, newRT); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  newAccessToken,
		RefreshToken: newPlainRT,
		TokenType:    "Bearer",
		ExpiresIn:    int64(m.cfg.AccessTTL.Seconds()),
		ExpiresAt:    time.Now().Add(m.cfg.AccessTTL),
	}, nil
}

// Verify parses, cryptographically verifies, and checks claims validity of a token.
func (m *Manager) Verify(tokenString string) (*Token, error) {
	tok, err := m.engine.Verify(tokenString)
	if err != nil {
		return nil, err
	}

	// Check if token's JTI is in revocation blacklist
	if tok.Claims.ID != "" {
		m.blackMu.RLock()
		exp, revoked := m.blacklist[tok.Claims.ID]
		m.blackMu.RUnlock()
		if revoked && time.Now().Before(exp) {
			return nil, ErrTokenRevoked
		}
	}

	// Validate RFC 7519 time constraints (exp, nbf, iat)
	if err := tok.Claims.Valid(m.cfg.ClockSkew); err != nil {
		return nil, err
	}

	// Validate Issuer if configured
	if m.cfg.Issuer != "" && tok.Claims.Issuer != "" && tok.Claims.Issuer != m.cfg.Issuer {
		return nil, ErrIssuerMismatch
	}

	// Validate Audience if configured
	if m.cfg.Audience != "" && tok.Claims.Audience != "" && tok.Claims.Audience != m.cfg.Audience {
		return nil, ErrAudienceMismatch
	}

	return tok, nil
}

// RevokeJTI revokes an individual token by its JTI until its natural expiration.
func (m *Manager) RevokeJTI(jti string, expiresAt time.Time) {
	if jti == "" {
		return
	}
	m.blackMu.Lock()
	defer m.blackMu.Unlock()
	m.blacklist[jti] = expiresAt
}
