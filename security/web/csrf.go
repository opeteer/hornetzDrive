package web

import (
	"net/http"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// HardenedCSRF returns a strict CSRF middleware utilizing the Double-Submit Cookie pattern
// with SameSite=Strict and Secure cookie settings to prevent cross-origin forgery.
func HardenedCSRF() echo.MiddlewareFunc {
	config := middleware.CSRFConfig{
		TokenLookup:    "header:X-CSRF-Token",
		CookiePath:     "/",
		CookieSecure:   true,                    // Enforce HTTPS
		CookieHTTPOnly: false,                   // JS needs to read the token to send it in the header
		CookieSameSite: http.SameSiteStrictMode, // Prevent sending cookie on cross-site requests
	}
	return middleware.CSRFWithConfig(config)
}
