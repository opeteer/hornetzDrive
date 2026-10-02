package fullstack

import (
	"context"
	"fmt"
	"reflect"

	"github.com/labstack/echo/v5"
)

// Render executes a Templ component and writes it directly to the Echo response stream.
// It automatically sets the Content-Type to "text/html; charset=utf-8" and writes the HTTP status code.
// Because Templ components render to an io.Writer, this operation uses minimal memory allocation.
func Render(c *echo.Context, statusCode int, cmp Component) error {
	c.Response().Header().Set(echo.HeaderContentType, echo.MIMETextHTMLCharsetUTF8)
	c.Response().WriteHeader(statusCode)

	// Inject CSRF token into request context so Templ components can use CSRFTokenCtx(ctx)
	ctx := c.Request().Context()
	token := CSRFToken(c)
	if token != "" {
		ctx = context.WithValue(ctx, csrfContextKey{}, token)
	}

	// Stream the compiled Go template output directly into the HTTP response body
	return cmp.Render(ctx, c.Response())
}

// RenderLayout intelligently renders a component wrapped inside an outer layout shell.
// Ztatic HOTW optimization: If the incoming request originates from a Turbo Frame 
// (detected via the "Turbo-Frame" HTTP header), it completely bypasses the outer layout
// and renders only the inner content component. This cuts network bandwidth by up to 80%
// during SPA-like frame navigations.
//
// layout can be a fullstack.LayoutFunc, a func(Component) Component, a Templ layout
// func(templ.Component) templ.Component, or any function taking and returning a Component.
func RenderLayout(c *echo.Context, statusCode int, layout any, content Component) error {
	if IsTurboFrame(c) {
		// Turbo Frame navigation: Render only the inner content fragment
		return Render(c, statusCode, content)
	}

	// Direct fast-path for LayoutFunc or func(Component) Component
	switch fn := layout.(type) {
	case LayoutFunc:
		return Render(c, statusCode, fn(content))
	case func(Component) Component:
		return Render(c, statusCode, fn(content))
	}

	// Dynamic invocation for Templ generated layouts (e.g. func(templ.Component) templ.Component)
	val := reflect.ValueOf(layout)
	if val.Kind() == reflect.Func && val.Type().NumIn() == 1 && val.Type().NumOut() == 1 {
		inType := val.Type().In(0)
		contentVal := reflect.ValueOf(content)
		if contentVal.Type().AssignableTo(inType) {
			res := val.Call([]reflect.Value{contentVal})
			if cmp, ok := res[0].Interface().(Component); ok {
				return Render(c, statusCode, cmp)
			}
		}
	}

	return fmt.Errorf("fullstack: unsupported layout function type: %T", layout)
}
