package web

import (
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// HardenedCSRF returns a CSRF middleware with relaxed settings for high interface responsiveness.
func HardenedCSRF() echo.MiddlewareFunc {
	return HardenedCSRFWithConfig(DefaultCSRFConfig())
}

// HardenedCSRFWithConfig returns a CSRF middleware with config.
func HardenedCSRFWithConfig(cfg middleware.CSRFConfig) echo.MiddlewareFunc {
	return middleware.CSRFWithConfig(cfg)
}

