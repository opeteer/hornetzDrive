package fullstack

import (
	"context"
	"io"
)

// Component is a shim for github.com/a-h/templ.Component.
// It defines the standard interface for a Templ component,
// allowing Ztatic to compile and type-check without external network dependencies.
type Component interface {
	Render(ctx context.Context, w io.Writer) error
}

// LayoutFunc represents a higher-order component that wraps inner content,
// typically used for rendering an application shell (HTML head, body, navbar, footer).
type LayoutFunc func(content Component) Component
