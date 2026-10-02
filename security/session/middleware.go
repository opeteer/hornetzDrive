package session

import (
	"net/http"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"ztatic-go-framework/errors"
)

// ContextKeySession is the Echo context key holding the active *Session.
const ContextKeySession = "ztatic_session"

// SessionConfig defines configuration for the session management middleware.
type SessionConfig struct {
	Skipper         middleware.Skipper
	Store           Store
	CookieName      string
	CookiePath      string
	CookieDomain    string
	CookieSecure    bool
	CookieHTTPOnly  bool
	CookieSameSite  http.SameSite
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
}

// DefaultSessionConfig returns secure default configuration with HttpOnly, SameSite=Lax,
// 30-minute idle sliding timeout, and 8-hour absolute session ceiling.
func DefaultSessionConfig(store Store) SessionConfig {
	return SessionConfig{
		Skipper:         middleware.DefaultSkipper,
		Store:           store,
		CookieName:      "ztatic_session",
		CookiePath:      "/",
		CookieSecure:    false,
		CookieHTTPOnly:  true,
		CookieSameSite:  http.SameSiteLaxMode,
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 8 * time.Hour,
	}
}

// Middleware returns a session middleware configured with default options.
func Middleware(store Store) echo.MiddlewareFunc {
	return MiddlewareWithConfig(DefaultSessionConfig(store))
}

// MiddlewareWithConfig returns a session middleware configured with custom settings.
func MiddlewareWithConfig(cfg SessionConfig) echo.MiddlewareFunc {
	if cfg.Skipper == nil {
		cfg.Skipper = middleware.DefaultSkipper
	}
	if cfg.CookieName == "" {
		cfg.CookieName = "ztatic_session"
	}
	if cfg.CookiePath == "" {
		cfg.CookiePath = "/"
	}
	if cfg.CookieSameSite == 0 {
		cfg.CookieSameSite = http.SameSiteLaxMode
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = 30 * time.Minute
	}
	if cfg.AbsoluteTimeout <= 0 {
		cfg.AbsoluteTimeout = 8 * time.Hour
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			if cfg.Store == nil {
				return errors.Internal("Session store is not configured")
			}

			var sess *Session
			ctx := c.Request().Context()

			// 1. Read existing session cookie
			cookie, err := c.Cookie(cfg.CookieName)
			if err == nil && cookie != nil && cookie.Value != "" {
				loaded, getErr := cfg.Store.Get(ctx, cookie.Value)
				if getErr == nil && loaded != nil {
					// Enforce Absolute Timeout (Force re-authentication after set ceiling)
					if cfg.AbsoluteTimeout > 0 && time.Since(loaded.CreatedAt) > cfg.AbsoluteTimeout {
						_ = cfg.Store.Destroy(ctx, loaded.ID)
						sess = NewSession(cfg.IdleTimeout)
					} else {
						// Session is valid; refresh idle activity timestamp
						loaded.Touch(cfg.IdleTimeout)
						sess = loaded
					}
				}
			}

			// 2. Fallback to a newly generated session if missing or expired
			if sess == nil {
				sess = NewSession(cfg.IdleTimeout)
			}

			// Store in context for downstream handlers
			c.Set(ContextKeySession, sess)

			// Protect against browser caching responses that transmit session cookies
			c.Response().Header().Add(echo.HeaderVary, echo.HeaderCookie)

			// 3. Deferred commit hook: ensures cookies and storage writes occur before headers commit
			var commitOnce sync.Once
			commitSession := func() {
				commitOnce.Do(func() {
					if sess.IsDestroyed() {
						_ = cfg.Store.Destroy(ctx, sess.ID)
						c.SetCookie(&http.Cookie{
							Name:     cfg.CookieName,
							Value:    "",
							Path:     cfg.CookiePath,
							Domain:   cfg.CookieDomain,
							MaxAge:   -1,
							HttpOnly: cfg.CookieHTTPOnly,
							Secure:   cfg.CookieSecure,
							SameSite: cfg.CookieSameSite,
						})
						return
					}

					// If RegenerateID was called, purge the old session ID from storage
					if oldID := sess.OldID(); oldID != "" && oldID != sess.ID {
						_ = cfg.Store.Destroy(ctx, oldID)
					}

					if sess.IsModified() || sess.IsNew() {
						_ = cfg.Store.Save(ctx, sess, cfg.IdleTimeout)
						c.SetCookie(&http.Cookie{
							Name:     cfg.CookieName,
							Value:    sess.ID,
							Path:     cfg.CookiePath,
							Domain:   cfg.CookieDomain,
							MaxAge:   int(cfg.IdleTimeout.Seconds()),
							HttpOnly: cfg.CookieHTTPOnly,
							Secure:   cfg.CookieSecure,
							SameSite: cfg.CookieSameSite,
						})
						return
					}

					// Untouched existing session: touch backend TTL
					_ = cfg.Store.Touch(ctx, sess.ID, cfg.IdleTimeout)
				})
			}

			// Hook into Echo's response writer before headers commit if underlying writer is *echo.Response
			if resp, ok := c.Response().(*echo.Response); ok {
				resp.Before(commitSession)
			}

			// Execute handler chain
			handlerErr := next(c)

			// Final safety commit in case Response.Before was not invoked
			commitSession()

			return handlerErr
		}
	}
}

// FromContext retrieves the active *Session from an Echo context.
func FromContext(c *echo.Context) *Session {
	if c == nil {
		return nil
	}
	if val := c.Get(ContextKeySession); val != nil {
		if sess, ok := val.(*Session); ok {
			return sess
		}
	}
	return nil
}
