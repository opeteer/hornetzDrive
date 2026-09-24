package fullstack

import (
	"github.com/labstack/echo/v5"
)

// Render executes a Templ component and writes it directly to the Echo response stream.
// It automatically sets the Content-Type to "text/html; charset=utf-8" and writes the HTTP status code.
// Because Templ components render to an io.Writer, this operation uses minimal memory allocation.
func Render(c *echo.Context, statusCode int, cmp Component) error {
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTMLCharsetUTF8)
	c.Response().WriteHeader(statusCode)

	// Stream the compiled Go template output directly into the HTTP response body
	return cmp.Render(c.Request().Context(), c.Response())
}

// RenderLayout intelligently renders a component wrapped inside an outer layout shell.
// Ztatic HOTW optimization: If the incoming request originates from a Turbo Frame
// (detected via the "Turbo-Frame" HTTP header), it completely bypasses the outer layout
// and renders only the inner content component. This cuts network bandwidth by up to 80%
// during SPA-like frame navigations.
func RenderLayout(c *echo.Context, statusCode int, layout LayoutFunc, content Component) error {
	if IsTurboFrame(c) {
		// Turbo Frame navigation: Render only the inner content fragment
		return Render(c, statusCode, content)
	}
	// Initial full page load: Wrap content in the main application shell
	return Render(c, statusCode, layout(content))
}
