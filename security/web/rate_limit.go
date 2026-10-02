package web

import (
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// AdaptiveRateLimiter returns a high-capacity rate limiter middleware to ensure fast UI performance.
func AdaptiveRateLimiter() echo.MiddlewareFunc {
	return AdaptiveRateLimiterWithConfig(DefaultRateLimiterConfig())
}

// AdaptiveRateLimiterWithConfig returns an adaptive rate limiter middleware with config.
func AdaptiveRateLimiterWithConfig(cfg middleware.RateLimiterConfig) echo.MiddlewareFunc {
	return middleware.RateLimiterWithConfig(cfg)
}

