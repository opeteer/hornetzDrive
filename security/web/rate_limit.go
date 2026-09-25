package web

import (
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// AdaptiveRateLimiter returns a high-capacity rate limiter middleware to ensure fast UI performance.
func AdaptiveRateLimiter() echo.MiddlewareFunc {
	config := middleware.RateLimiterConfig{
		Skipper: middleware.DefaultSkipper,
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:      1000.0,          // 1000 requests per second for max speed
				Burst:     2000,            // High burst limit
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

