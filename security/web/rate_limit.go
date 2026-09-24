package web

import (
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// AdaptiveRateLimiter returns an IP-based rate limiter middleware to prevent DoS attacks.
func AdaptiveRateLimiter() echo.MiddlewareFunc {
	config := middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:      20.0,            // 20 requests per second
				Burst:     50,              // Burst up to 50 requests
				ExpiresIn: 3 * time.Minute, // Expire inactive records after 3 minutes
			},
		),
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			return c.RealIP(), nil
		},
		ErrorHandler: func(c *echo.Context, err error) error {
			return echo.NewHTTPError(429, "Too Many Requests")
		},
		DenyHandler: func(c *echo.Context, identifier string, err error) error {
			c.Logger().Warn("Rate limit exceeded", "ip", identifier)
			return echo.NewHTTPError(429, "Rate limit exceeded. Please try again later.")
		},
	}
	return middleware.RateLimiterWithConfig(config)
}
