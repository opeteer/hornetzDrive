package upload

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/errors"
)

const (
	// ContextUploadMaxBodyKey stores the route-specific body size limit in the Echo context.
	ContextUploadMaxBodyKey = "ztatic_upload_max_body"
	// ContextUploadRouteKey flags the route as a designated file upload endpoint for the WAF.
	ContextUploadRouteKey = "ztatic_upload_route"
)

// RouteLimit enforces a dedicated request body size limit for file upload endpoints,
// overriding the global WAF 128KB limit for this specific route while protecting against DoS.
func RouteLimit(maxBytes int64) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			// Signal to WAF that this is a recognized upload route with higher limit
			c.Set(ContextUploadRouteKey, true)
			c.Set(ContextUploadMaxBodyKey, maxBytes)

			req := c.Request()
			if req.ContentLength > maxBytes {
				return errors.New("PAYLOAD_TOO_LARGE", fmt.Sprintf("Request payload exceeds limit of %d bytes", maxBytes)).
					WithStatus(http.StatusRequestEntityTooLarge)
			}

			// Wrap request body to enforce streaming read limit
			if req.Body != nil {
				req.Body = http.MaxBytesReader(c.Response(), req.Body, maxBytes)
			}

			return next(c)
		}
	}
}

// AutoCleanup automatically removes any temporary disk files created by multipart form parsing
// once the HTTP request handling completes.
func AutoCleanup() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			err := next(c)
			if c.Request().MultipartForm != nil {
				_ = c.Request().MultipartForm.RemoveAll()
			}
			return err
		}
	}
}
