package web

import (
	"github.com/labstack/echo/v5"
)

// SecureHeaders returns a middleware that sets Zero-Trust HTTP security headers
// to protect against XSS, clickjacking, MIME-sniffing, and MITM attacks.
func SecureHeaders() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			res := c.Response()

			// Basic security headers
			res.Header().Set("X-XSS-Protection", "1; mode=block")
			res.Header().Set("X-Content-Type-Options", "nosniff")
			res.Header().Set("X-Frame-Options", "DENY")

			// HSTS (Strict-Transport-Security)
			res.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")

			// Content-Security-Policy (CSP) adapted for Hornetz Drive (allows Web Workers via blob: and inline styles for DOM Virtualization)
			res.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' blob:; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests;")

			// Cross-Origin policies (COOP, COEP, CORP)
			res.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
			res.Header().Set("Cross-Origin-Embedder-Policy", "require-corp")
			res.Header().Set("Cross-Origin-Resource-Policy", "same-origin")

			// Referrer-Policy
			res.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

			// Permissions-Policy (Feature-Policy successor)
			res.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")

			return next(c)
		}
	}
}
