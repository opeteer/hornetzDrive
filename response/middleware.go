package response

import (
	"time"

	"github.com/labstack/echo/v5"
)

// Middleware returns an Echo middleware that records request start time
// enabling duration tracking in response metadata.
func Middleware() echo.MiddlewareFunc {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns an Echo middleware configured with custom settings.
func MiddlewareWithConfig(cfg Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.EnableDurationMeta {
				c.Set(ContextKeyStartTime, time.Now())
			}
			return next(c)
		}
	}
}
