package token

import (
	"errors"
	"strings"
	"time"

	"ztatic-go-framework/security/audit"
)

var (
	ErrTokenExpired          = errors.New("ztatic/token: token has expired")
	ErrTokenNotValidYet      = errors.New("ztatic/token: token is not valid yet")
	ErrTokenUsedBeforeIssued = errors.New("ztatic/token: token was used before it was issued")
	ErrInvalidToken          = errors.New("ztatic/token: invalid token format")
	ErrInvalidSignature      = errors.New("ztatic/token: invalid token signature")
	ErrAlgorithmMismatch     = errors.New("ztatic/token: token algorithm is not allowed or invalid")
	ErrInvalidKey            = errors.New("ztatic/token: key must be at least 32 bytes (256 bits) for HMAC-SHA256")
	ErrTokenRevoked          = errors.New("ztatic/token: token has been revoked")
	ErrRefreshTokenReused    = errors.New("ztatic/token: refresh token reuse detected; token family revoked")
	ErrAudienceMismatch      = errors.New("ztatic/token: audience mismatch")
	ErrIssuerMismatch        = errors.New("ztatic/token: issuer mismatch")
)

// StandardClaims encapsulates standard RFC 7519 registered claims.
type StandardClaims struct {
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	ID        string `json:"jti,omitempty"`
}

// Claims defines standard and domain claims for authentication and authorization.
type Claims struct {
	StandardClaims
	Roles    []string       `json:"roles,omitempty"`
	Scopes   []string       `json:"scopes,omitempty"`
	TenantID string         `json:"tenant_id,omitempty"`
	Email    string         `json:"email,omitempty"`
	Extra    map[string]any `json:"extra,omitempty"`
}

// Valid validates the expiration, not-before, and issued-at times against current time
// with an optional clock skew leeway.
func (c *StandardClaims) Valid(clockSkew time.Duration) error {
	now := time.Now().Unix()
	leeway := int64(clockSkew.Seconds())

	if c.ExpiresAt > 0 && now > (c.ExpiresAt+leeway) {
		return ErrTokenExpired
	}
	if c.NotBefore > 0 && now < (c.NotBefore-leeway) {
		return ErrTokenNotValidYet
	}
	if c.IssuedAt > 0 && now < (c.IssuedAt-leeway) {
		return ErrTokenUsedBeforeIssued
	}
	return nil
}

// Valid checks standard claims validity on Claims.
func (c *Claims) Valid(clockSkew time.Duration) error {
	if c == nil {
		return ErrInvalidToken
	}
	return c.StandardClaims.Valid(clockSkew)
}

// HasRole returns true if the claims contain the specified role (case-insensitive).
func (c *Claims) HasRole(role string) bool {
	if c == nil {
		return false
	}
	for _, r := range c.Roles {
		if strings.EqualFold(r, role) {
			return true
		}
	}
	return false
}

// HasAnyRole returns true if the claims contain at least one of the specified roles.
func (c *Claims) HasAnyRole(roles ...string) bool {
	if c == nil || len(roles) == 0 {
		return false
	}
	for _, role := range roles {
		if c.HasRole(role) {
			return true
		}
	}
	return false
}

// HasScope returns true if the claims contain the specified OAuth2/permission scope.
func (c *Claims) HasScope(scope string) bool {
	if c == nil {
		return false
	}
	for _, s := range c.Scopes {
		if s == scope || s == "*" {
			return true
		}
	}
	return false
}

// HasAllScopes returns true if the claims contain all specified scopes.
func (c *Claims) HasAllScopes(scopes ...string) bool {
	if c == nil {
		return false
	}
	for _, scope := range scopes {
		if !c.HasScope(scope) {
			return false
		}
	}
	return true
}

// InTenant returns true if the claims match the specified tenant ID.
func (c *Claims) InTenant(tenantID string) bool {
	if c == nil {
		return false
	}
	return c.TenantID == tenantID
}

// PrimaryRole returns the first role listed or empty string.
func (c *Claims) PrimaryRole() string {
	if c != nil && len(c.Roles) > 0 {
		return c.Roles[0]
	}
	return ""
}

// ToAuditActor maps claims to a compliance audit Actor record.
func (c *Claims) ToAuditActor(ip string) audit.Actor {
	actor := audit.Actor{
		Type:     "user",
		IP:       ip,
		Metadata: make(map[string]any),
	}
	if c == nil {
		actor.Type = "anonymous"
		return actor
	}

	actor.ID = c.Subject
	actor.Role = c.PrimaryRole()
	actor.TenantID = c.TenantID

	if c.Email != "" {
		actor.Metadata["email"] = c.Email
	}
	if len(c.Roles) > 1 {
		actor.Metadata["roles"] = c.Roles
	}
	if len(c.Scopes) > 0 {
		actor.Metadata["scopes"] = c.Scopes
	}
	if c.ID != "" {
		actor.Metadata["jti"] = c.ID
	}
	return actor
}

// GenericClaims allows type-safe domain payload embedding while preserving RFC 7519 validation.
type GenericClaims[T any] struct {
	StandardClaims
	Data T `json:"data"`
}

// Valid checks validity of standard claims within generic claims.
func (g *GenericClaims[T]) Valid(clockSkew time.Duration) error {
	if g == nil {
		return ErrInvalidToken
	}
	return g.StandardClaims.Valid(clockSkew)
}
