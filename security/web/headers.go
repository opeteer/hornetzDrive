package web

import (
	"github.com/labstack/echo/v5"
)

// SecureHeaders returns a middleware with relaxed security headers for optimal speed
// and compatibility with external CDNs and frontend frameworks.
func SecureHeaders() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			res := c.Response()

			// Basic headers
			res.Header().Set("X-XSS-Protection", "1; mode=block")
			res.Header().Set("X-Content-Type-Options", "nosniff")
			res.Header().Set("X-Frame-Options", "SAMEORIGIN")

			// Relaxed Content-Security-Policy to allow inline scripts, Tailwind, AlpineJS, and fonts
			res.Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; font-src * data:; style-src * 'unsafe-inline'; script-src * 'unsafe-inline' 'unsafe-eval' blob:;")

			// Referrer Policy
			res.Header().Set("Referrer-Policy", "no-referrer-when-downgrade")

			return next(c)
		}
	}
}

