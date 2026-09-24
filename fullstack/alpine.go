package fullstack

import (
	"github.com/labstack/echo/v5"
)

// AlpineMorphHeader is an optional header used to signal to the client
// that the incoming Turbo Stream contains stateful Alpine.js components
// and should be morphed using @alpinejs/morph rather than a hard DOM replacement.
const AlpineMorphHeader = "X-Alpine-Morph"

// EnableAlpineMorphing sets the morph header on the response.
// The client-side Hotwire setup must listen for this header to apply Alpine.morph().
func EnableAlpineMorphing(c *echo.Context) {
	c.Response().Header().Set(AlpineMorphHeader, "enabled")
}
