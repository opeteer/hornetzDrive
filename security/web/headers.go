package web

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"

	"github.com/labstack/echo/v5"
)

// SecureHeaders returns a middleware with security headers for optimal speed
// and modern web protection (HSTS, CSP nonces, nosniff, frame options).
func SecureHeaders() echo.MiddlewareFunc {
	return SecureHeadersWithConfig(DefaultHeaderConfig())
}

// SecureHeadersWithConfig returns a SecureHeaders middleware with config.
func SecureHeadersWithConfig(cfg HeaderConfig) echo.MiddlewareFunc {
	if cfg.Skipper == nil {
		cfg.Skipper = DefaultHeaderConfig().Skipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			res := c.Response()

			if cfg.XSSProtection != "" {
				res.Header().Set("X-XSS-Protection", cfg.XSSProtection)
			}
			if cfg.ContentTypeOptions != "" {
				res.Header().Set("X-Content-Type-Options", cfg.ContentTypeOptions)
			}
			if cfg.FrameOptions != "" {
				res.Header().Set("X-Frame-Options", cfg.FrameOptions)
			}
			if cfg.StrictTransportSecurity != "" {
				res.Header().Set("Strict-Transport-Security", cfg.StrictTransportSecurity)
			}
			if cfg.ReferrerPolicy != "" {
				res.Header().Set("Referrer-Policy", cfg.ReferrerPolicy)
			}

			csp := cfg.ContentSecurityPolicy
			if cfg.EnableCSPNonce {
				nonceBytes := make([]byte, 16)
				if _, err := io.ReadFull(rand.Reader, nonceBytes); err == nil {
					nonce := base64.RawStdEncoding.EncodeToString(nonceBytes)
					c.Set("csp_nonce", nonce)
					if strings.Contains(csp, "{NONCE}") {
						csp = strings.ReplaceAll(csp, "{NONCE}", nonce)
					} else if strings.Contains(csp, "script-src") {
						csp = strings.Replace(csp, "script-src", "script-src 'nonce-"+nonce+"'", 1)
					} else if csp != "" {
						csp = csp + "; script-src 'nonce-" + nonce + "'"
					}
				}
			}
			if csp != "" {
				res.Header().Set("Content-Security-Policy", csp)
			}

			return next(c)
		}
	}
}

// GetCSPNonce extracts the per-request CSP nonce from context if present.
func GetCSPNonce(c *echo.Context) string {
	if c == nil {
		return ""
	}
	if nonce, ok := c.Get("csp_nonce").(string); ok {
		return nonce
	}
	return ""
}


