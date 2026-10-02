package token

import (
	"fmt"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"ztatic-go-framework/errors"
	"ztatic-go-framework/security/audit"
)

const (
	ContextKeyToken  = "ztatic_token"
	ContextKeyClaims = "ztatic_token_claims"
)

// TokenAuthConfig defines configuration for the Token authentication middleware.
type TokenAuthConfig struct {
	Skipper     middleware.Skipper
	Manager     *Manager
	TokenLookup string // e.g., "header:Authorization:Bearer ,cookie:token,query:token"
	Optional    bool   // If true, missing/invalid tokens do not abort request, allowing anonymous access
	ErrorHandler func(c *echo.Context, err error) error
}

// DefaultTokenAuthConfig returns secure default configuration for TokenAuth.
func DefaultTokenAuthConfig(manager *Manager) TokenAuthConfig {
	return TokenAuthConfig{
		Skipper:     middleware.DefaultSkipper,
		Manager:     manager,
		TokenLookup: "header:Authorization:Bearer ,cookie:token,query:token",
		Optional:    false,
		ErrorHandler: func(c *echo.Context, err error) error {
			return errors.Unauthorized("Authentication required: " + err.Error())
		},
	}
}

// TokenAuth returns a middleware configured with default options for the given manager.
func TokenAuth(manager *Manager) echo.MiddlewareFunc {
	return TokenAuthWithConfig(DefaultTokenAuthConfig(manager))
}

// TokenAuthWithConfig returns a token authentication middleware with custom configuration.
func TokenAuthWithConfig(cfg TokenAuthConfig) echo.MiddlewareFunc {
	if cfg.Skipper == nil {
		cfg.Skipper = middleware.DefaultSkipper
	}
	if cfg.TokenLookup == "" {
		cfg.TokenLookup = "header:Authorization:Bearer ,cookie:token,query:token"
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *echo.Context, err error) error {
			return errors.Unauthorized("Authentication required: " + err.Error())
		}
	}

	extractors, err := middleware.CreateExtractors(cfg.TokenLookup, 1)
	if err != nil {
		panic(fmt.Sprintf("ztatic/token: invalid token lookup configuration: %v", err))
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			if cfg.Manager == nil {
				return errors.Internal("Token manager not configured")
			}

			var rawToken string
			var lastExtractErr error

			for _, extractor := range extractors {
				tokens, _, err := extractor(c)
				if err == nil && len(tokens) > 0 && tokens[0] != "" {
					rawToken = tokens[0]
					break
				}
				if err != nil {
					lastExtractErr = err
				}
			}

			if rawToken == "" {
				if cfg.Optional {
					return next(c)
				}
				if lastExtractErr == nil {
					lastExtractErr = ErrInvalidToken
				}
				return cfg.ErrorHandler(c, lastExtractErr)
			}

			tok, err := cfg.Manager.Verify(rawToken)
			if err != nil {
				if cfg.Optional {
					return next(c)
				}
				return cfg.ErrorHandler(c, err)
			}

			// Store validated token and claims in Echo context
			c.Set(ContextKeyToken, tok)
			c.Set(ContextKeyClaims, tok.Claims)

			// Populate standard identity keys for downstream handlers & loggers
			if tok.Claims.Subject != "" {
				c.Set("user_id", tok.Claims.Subject)
			}
			if role := tok.Claims.PrimaryRole(); role != "" {
				c.Set("user_role", role)
			}
			if tok.Claims.TenantID != "" {
				c.Set("tenant_id", tok.Claims.TenantID)
			}

			// Synchronize with active Audit Logger entry if present
			if entry := audit.FromContext(c); entry != nil {
				entry.WithActorStruct(tok.Claims.ToAuditActor(c.RealIP()))
			}

			return next(c)
		}
	}
}

// FromContext extracts the validated Token from the Echo context.
func FromContext(c *echo.Context) *Token {
	if c == nil {
		return nil
	}
	if val := c.Get(ContextKeyToken); val != nil {
		if tok, ok := val.(*Token); ok {
			return tok
		}
	}
	return nil
}

// ClaimsFromContext extracts the validated Claims from the Echo context.
func ClaimsFromContext(c *echo.Context) *Claims {
	if c == nil {
		return nil
	}
	if val := c.Get(ContextKeyClaims); val != nil {
		if claims, ok := val.(*Claims); ok {
			return claims
		}
	}
	return nil
}

// RequireAuth ensures that a valid token exists on the request context.
func RequireAuth() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims := ClaimsFromContext(c)
			if claims == nil || claims.Subject == "" {
				return errors.Unauthorized("Authentication required")
			}
			return next(c)
		}
	}
}

// RequireRole guards a route requiring the user to hold at least one of the specified roles.
func RequireRole(roles ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims := ClaimsFromContext(c)
			if claims == nil {
				return errors.Unauthorized("Authentication required")
			}
			if !claims.HasAnyRole(roles...) {
				return errors.Forbidden("Insufficient role permissions")
			}
			return next(c)
		}
	}
}

// RequireScope guards a route requiring the user to possess all specified permission scopes.
func RequireScope(scopes ...string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims := ClaimsFromContext(c)
			if claims == nil {
				return errors.Unauthorized("Authentication required")
			}
			if !claims.HasAllScopes(scopes...) {
				return errors.Forbidden("Insufficient scope permissions")
			}
			return next(c)
		}
	}
}

// RequireTenant guards a route ensuring multi-tenant isolation.
func RequireTenant(tenantID string) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			claims := ClaimsFromContext(c)
			if claims == nil {
				return errors.Unauthorized("Authentication required")
			}
			if !claims.InTenant(tenantID) {
				return errors.Forbidden("Tenant access denied")
			}
			return next(c)
		}
	}
}
