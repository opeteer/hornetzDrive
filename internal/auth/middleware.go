package auth

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/data"
)

type userSessionEntry struct {
	UserID    int64
	ExpiresAt time.Time
}

var (
	userSessionMu sync.RWMutex
	userSessions  = make(map[string]userSessionEntry)
)

const (
	UserSessionCookieName = "hornetz_user_session"
	UserSessionTTL        = 30 * 24 * time.Hour
)

// CreateUserSession creates an active user session in memory for the given user ID.
func CreateUserSession(userID int64) string {
	userSessionMu.Lock()
	defer userSessionMu.Unlock()

	b := make([]byte, 24)
	_, _ = rand.Read(b)
	sessID := "usr_" + hex.EncodeToString(b)

	userSessions[sessID] = userSessionEntry{
		UserID:    userID,
		ExpiresAt: time.Now().Add(UserSessionTTL),
	}
	return sessID
}

// ValidateUserSession checks if a session ID is valid and unexpired, returning the user ID.
func ValidateUserSession(sessID string) (int64, bool) {
	if sessID == "" {
		return 0, false
	}
	userSessionMu.RLock()
	defer userSessionMu.RUnlock()

	entry, ok := userSessions[sessID]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return 0, false
	}
	return entry.UserID, true
}

// SetUserSessionCookie sets the user session cookie on the HTTP response.
func SetUserSessionCookie(c *echo.Context, sessID string) {
	c.SetCookie(&http.Cookie{
		Name:     UserSessionCookieName,
		Value:    sessID,
		Path:     "/",
		HttpOnly: true,
		Secure:   c.Scheme() == "https",
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(UserSessionTTL),
	})
}

// GetUserID extracts the authenticated user ID from context. Defaults to 1 for backwards compatibility.
func GetUserID(c *echo.Context) int64 {
	if uid, ok := c.Get("user_id").(int64); ok && uid > 0 {
		return uid
	}
	return 1
}

// EnsureDashboardSessionMiddleware ensures any user accessing UI routes has an authenticated session.
func EnsureDashboardSessionMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			cookie, err := c.Cookie(UserSessionCookieName)
			var userID int64
			var valid bool
			if err == nil && cookie != nil {
				userID, valid = ValidateUserSession(cookie.Value)
			}
			if !valid {
				sessID := CreateUserSession(1)
				SetUserSessionCookie(c, sessID)
				userID = 1
			}
			c.Set("user_id", userID)
			return next(c)
		}
	}
}

// RequireAuth middleware verifies that an API or Upload request has a valid user session.
func RequireAuth(db *data.DBEngine) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			var sessID string

			// 1. Check Bearer token in Authorization header
			authHeader := c.Request().Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				sessID = strings.TrimPrefix(authHeader, "Bearer ")
			}

			// 2. Fallback to user session cookie
			if sessID == "" {
				if cookie, err := c.Cookie(UserSessionCookieName); err == nil && cookie != nil {
					sessID = cookie.Value
				}
			}

			// 3. Fallback to swarm_session if unlocked
			if sessID == "" {
				if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
					if GlobalSessionStore.HasKey(cookie.Value) {
						c.Set("user_id", int64(1))
						return next(c)
					}
				}
			}

			if sessID != "" {
				if userID, ok := ValidateUserSession(sessID); ok {
					c.Set("user_id", userID)
					return next(c)
				}
			}

			// In development / single-user local dashboard environment, if requests come from loopback
			// and no session exists, lazily auto-provision session to ensure smooth UX.
			clientIP := c.RealIP()
			if clientIP == "127.0.0.1" || clientIP == "::1" || clientIP == "" {
				newSess := CreateUserSession(1)
				SetUserSessionCookie(c, newSess)
				c.Set("user_id", int64(1))
				return next(c)
			}

			return echo.NewHTTPError(http.StatusUnauthorized, "Unauthorized: valid user session or token required")
		}
	}
}
