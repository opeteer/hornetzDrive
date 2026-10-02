package audit

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// PolicyFunc evaluates whether an audit entry should be preserved and forwarded to the logger.
type PolicyFunc func(c *echo.Context, entry *Entry) bool

// DefaultAuditPolicy records mutating operations (POST, PUT, PATCH, DELETE) and any request resulting in an error (status >= 400).
func DefaultAuditPolicy(c *echo.Context, entry *Entry) bool {
	if entry.Outcome.StatusCode >= 400 {
		return true
	}

	method := entry.Context.Method
	if method == "" && c != nil && c.Request() != nil {
		method = c.Request().Method
	}

	switch strings.ToUpper(method) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		// Also capture any security/auth classifications regardless of HTTP method
		if entry.Category == CategoryAuth || entry.Category == CategoryAccess || entry.Category == CategorySecurity {
			return true
		}
		return false
	}
}

// AuditAllPolicy records every single transaction without exception.
func AuditAllPolicy(c *echo.Context, entry *Entry) bool {
	return true
}

// AuditSecurityOnlyPolicy records only authentication, authorization, or security-violation events.
func AuditSecurityOnlyPolicy(c *echo.Context, entry *Entry) bool {
	if entry.Outcome.StatusCode == 401 || entry.Outcome.StatusCode == 403 || entry.Outcome.StatusCode == 429 {
		return true
	}
	return entry.Category == CategoryAuth || entry.Category == CategoryAccess || entry.Category == CategorySecurity
}

// DefaultAuditSkipper ignores noise such as health probes, metrics, and static asset requests.
func DefaultAuditSkipper(c *echo.Context) bool {
	if c.Request() == nil || c.Request().URL == nil {
		return false
	}

	path := c.Request().URL.Path

	// Static assets
	if strings.HasPrefix(path, "/assets/") || strings.HasPrefix(path, "/dist/") || path == "/favicon.ico" {
		return true
	}

	// Health and liveness probes
	if path == "/health" || path == "/healthz" || path == "/livez" || path == "/readyz" || path == "/ping" {
		return true
	}

	// System metrics
	if path == "/metrics" {
		return true
	}

	return false
}
