package ztatic

import (
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"ztatic-go-framework/rapid"
	"ztatic-go-framework/security/web"
)

// Engine represents the Ztatic Framework engine, wrapping Echo v5
// with enterprise-grade Zero-Trust Security defaults.
type Engine struct {
	*echo.Echo
}

// NewSecure initializes a new Ztatic Engine pre-wired with the complete
// Zero-Trust Web Security Suite. It is safe by default.
func NewSecure() *Engine {
	e := echo.New()

	// Core robust middleware
	e.Use(middleware.Recover())

	// Phase 2: Web Security Hardening Pipeline
	// 1. Zero-Trust Security Headers (CSP, HSTS, COOP, CORP, etc.)
	e.Use(web.SecureHeaders())

	// 2. Web Application Firewall (WAF) for SQLi, XSS, and Traversal protection
	e.Use(web.WAF())

	// 3. Hardened CSRF Protection (SameSite=Strict, Secure)
	e.Use(web.HardenedCSRF())

	// 4. Adaptive Rate Limiting to prevent DoS attacks
	e.Use(web.AdaptiveRateLimiter())

	// Register the high-performance Struct Validator for Rapid DX
	e.Validator = rapid.NewStructValidator()

	return &Engine{Echo: e}
}

// New creates a raw Ztatic Engine without the full security pipeline,
// primarily for internal services or APIs behind another gateway.
func New() *Engine {
	e := echo.New()
	e.Use(middleware.Recover())
	return &Engine{Echo: e}
}
