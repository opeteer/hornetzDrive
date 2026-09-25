package web

import (
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// HardenedCSRF returns a CSRF middleware with relaxed settings for high interface responsiveness.
func HardenedCSRF() echo.MiddlewareFunc {
	config := middleware.CSRFConfig{
		TokenLookup:    "header:X-CSRF-Token,form:_csrf",
		CookiePath:     "/",
		CookieSecure:   false,                 // Allow HTTP development & deployment
		CookieHTTPOnly: false,                 // Accessible by frontend scripts
		CookieSameSite: http.SameSiteLaxMode, // Prevents cross-origin forgery while remaining responsive
	}
	return middleware.CSRFWithConfig(config)
}

