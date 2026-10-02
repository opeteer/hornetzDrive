package web

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"ztatic-go-framework/security/audit"
)

// Config defines the top-level configuration for the web security middleware suite.
type Config struct {
	EnableHeaders     bool
	EnableWAF         bool
	EnableCSRF        bool
	EnableRateLimiter bool
	EnableAudit       bool

	Headers     HeaderConfig
	WAF         WAFConfig
	CSRF        middleware.CSRFConfig
	RateLimiter middleware.RateLimiterConfig
	Audit       audit.AuditConfig
}

// HeaderConfig defines the configuration for the SecureHeaders middleware.
type HeaderConfig struct {
	Skipper                 middleware.Skipper
	XSSProtection           string
	ContentTypeOptions      string
	FrameOptions            string
	ContentSecurityPolicy   string
	StrictTransportSecurity string
	EnableCSPNonce          bool
	ReferrerPolicy          string
}

// WAFConfig defines the configuration for the Web Application Firewall middleware.
type WAFConfig struct {
	Skipper     middleware.Skipper
	MaxBodySize int64
}

// DefaultConfig returns the standard security-hardened configuration.
func DefaultConfig() Config {
	return Config{
		EnableHeaders:     true,
		EnableWAF:         true,
		EnableCSRF:        true,
		EnableRateLimiter: true,
		EnableAudit:       true,

		Headers:     DefaultHeaderConfig(),
		WAF:         DefaultWAFConfig(),
		CSRF:        DefaultCSRFConfig(),
		RateLimiter: DefaultRateLimiterConfig(),
		Audit:       audit.DefaultAuditConfig(),
	}
}

// DefaultHeaderConfig returns the default configuration for SecureHeaders.
func DefaultHeaderConfig() HeaderConfig {
	return HeaderConfig{
		Skipper:                 middleware.DefaultSkipper,
		XSSProtection:           "1; mode=block",
		ContentTypeOptions:      "nosniff",
		FrameOptions:            "SAMEORIGIN",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
		EnableCSPNonce:          true,
		ContentSecurityPolicy:   "default-src 'self'; font-src 'self' data: https:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-eval' https:; img-src 'self' data: blob: https:; connect-src 'self' ws: wss:;",
		ReferrerPolicy:          "no-referrer-when-downgrade",
	}
}

// DefaultWAFConfig returns the default configuration for the WAF.
func DefaultWAFConfig() WAFConfig {
	return WAFConfig{
		Skipper:     middleware.DefaultSkipper,
		MaxBodySize: 128 * 1024,
	}
}

// DefaultCSRFConfig returns the default configuration for CSRF protection.
func DefaultCSRFConfig() middleware.CSRFConfig {
	return middleware.CSRFConfig{
		Skipper: func(c *echo.Context) bool {
			path := c.Request().URL.Path
			// Sensitive mutating endpoints require CSRF protection
			if path == "/api/purge" || strings.HasPrefix(path, "/api/files") || strings.HasPrefix(path, "/api/vault") || strings.HasPrefix(path, "/api/folders") {
				if c.Request().Method == http.MethodPost || c.Request().Method == http.MethodDelete || c.Request().Method == http.MethodPut || c.Request().Method == http.MethodPatch {
					return false
				}
			}
			return path == "/api" || strings.HasPrefix(path, "/api/") ||
				path == "/docs" || strings.HasPrefix(path, "/docs/") ||
				strings.HasPrefix(path, "/v1/") ||
				strings.HasPrefix(path, "/v2/") ||
				strings.HasPrefix(path, "/rest/")
		},
		TokenLookup:    "header:X-CSRF-Token,form:_csrf",
		CookiePath:     "/",
		CookieSecure:   false,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteLaxMode,
	}
}

// DefaultRateLimiterConfig returns the default configuration for adaptive rate limiting.
func DefaultRateLimiterConfig() middleware.RateLimiterConfig {
	return middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:      1000.0,
				Burst:     2000,
				ExpiresIn: 3 * time.Minute,
			},
		),
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			return c.RealIP(), nil
		},
		ErrorHandler: func(c *echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, "Too Many Requests")
		},
		DenyHandler: func(c *echo.Context, identifier string, err error) error {
			c.Logger().Warn("Rate limit exceeded", "ip", identifier)
			return echo.NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded. Please try again later.")
		},
	}
}

// AuthRateLimiterConfig returns a strict rate limiter for authentication endpoints like /login.
func AuthRateLimiterConfig() middleware.RateLimiterConfig {
	return middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:      5.0 / 60.0, // 5 requests per minute
				Burst:     10,
				ExpiresIn: 5 * time.Minute,
			},
		),
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			return c.RealIP(), nil
		},
		ErrorHandler: func(c *echo.Context, err error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, "Too Many Requests")
		},
		DenyHandler: func(c *echo.Context, identifier string, err error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, "Too many login attempts. Please wait before trying again.")
		},
	}
}
