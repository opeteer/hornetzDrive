package fullstack

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// HotwireMiddleware intercepts incoming HTTP requests to analyze Hotwire Turbo headers.
// It sets contextual flags (`IsTurboFrame`, `IsTurboStream`) that can be accessed
// by downstream handlers and layout templates for intelligent rendering decisions.
func HotwireMiddleware() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := c.Request()

			// Detect if the client is expecting a Turbo Stream response
			acceptHeader := req.Header.Get(echo.HeaderAccept)
			if strings.Contains(acceptHeader, MIMETurboStream) {
				c.Set("IsTurboStream", true)
			}

			// Detect if the request originates from a Turbo Frame isolation boundary
			if frame := req.Header.Get(HeaderTurboFrame); frame != "" {
				c.Set("IsTurboFrame", true)
				c.Set("TurboFrameID", frame)
			}

			return next(c)
		}
	}
}
