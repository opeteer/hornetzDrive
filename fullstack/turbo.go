package fullstack

import (
	"bytes"
	"context"
	"fmt"
	"html"

	"github.com/labstack/echo/v5"
)

// HeaderTurboFrame is the HTTP header sent by Turbo Drive when requesting a frame update.
const HeaderTurboFrame = "Turbo-Frame"

// MIMETurboStream is the strict MIME type required by Hotwire to process DOM mutations.
const MIMETurboStream = "text/vnd.turbo-stream.html; charset=utf-8"

// IsTurboFrame detects if the incoming request is a Hotwire Turbo Frame request.
func IsTurboFrame(c *echo.Context) bool {
	return c.Request().Header.Get(HeaderTurboFrame) != ""
}

// GetTurboFrameID returns the requested Turbo Frame ID, useful for dynamic server rendering logic.
func GetTurboFrameID(c *echo.Context) string {
	return c.Request().Header.Get(HeaderTurboFrame)
}

// TurboStreamAction defines the 7 standard DOM mutation verbs supported by Hotwire.
type TurboStreamAction string

const (
	StreamAppend  TurboStreamAction = "append"
	StreamPrepend TurboStreamAction = "prepend"
	StreamReplace TurboStreamAction = "replace"
	StreamUpdate  TurboStreamAction = "update"
	StreamRemove  TurboStreamAction = "remove"
	StreamBefore  TurboStreamAction = "before"
	StreamAfter   TurboStreamAction = "after"
	StreamRefresh TurboStreamAction = "refresh"
)

// TurboStreamItem represents a single DOM mutation fragment.
type TurboStreamItem struct {
	Action    TurboStreamAction
	Target    string    // The DOM ID to mutate
	Component Component // The Templ component to render inside the template tags. Can be nil for StreamRemove.
}

// RenderTurboStream renders a single Hotwire Turbo Stream DOM mutation fragment
// directly to the client. It wraps the Templ component automatically inside <turbo-stream> tags.
// Both action and target attributes are strictly HTML-escaped to prevent DOM/XSS injection.
func RenderTurboStream(c *echo.Context, action TurboStreamAction, target string, cmp Component) error {
	c.Response().Header().Set(echo.HeaderContentType, MIMETurboStream)
	c.Response().WriteHeader(200)

	escapedAction := html.EscapeString(string(action))
	escapedTarget := html.EscapeString(target)
	_, err := fmt.Fprintf(c.Response(), `<turbo-stream action="%s" target="%s"><template>`, escapedAction, escapedTarget)
	if err != nil {
		return err
	}

	if cmp != nil {
		if err := cmp.Render(c.Request().Context(), c.Response()); err != nil {
			return err
		}
	}

	_, err = fmt.Fprint(c.Response(), `</template></turbo-stream>`)
	return err
}

// RenderTurboStreamMulti allows rendering multiple Turbo Stream actions in a single HTTP response.
// This is highly powerful for updating multiple disjoint parts of a page simultaneously.
func RenderTurboStreamMulti(c *echo.Context, streams ...TurboStreamItem) error {
	c.Response().Header().Set(echo.HeaderContentType, MIMETurboStream)
	c.Response().WriteHeader(200)

	for _, stream := range streams {
		escapedAction := html.EscapeString(string(stream.Action))
		escapedTarget := html.EscapeString(stream.Target)
		fmt.Fprintf(c.Response(), `<turbo-stream action="%s" target="%s"><template>`, escapedAction, escapedTarget)
		if stream.Component != nil {
			if err := stream.Component.Render(c.Request().Context(), c.Response()); err != nil {
				return err
			}
		}
		fmt.Fprint(c.Response(), `</template></turbo-stream>`)
	}
	return nil
}

// RenderStreamToString compiles a Turbo Stream item into a raw HTML string. 
// This is primarily used by the Realtime Event Broker to format messages for Server-Sent Events (SSE) broadcasting.
func RenderStreamToString(ctx context.Context, stream TurboStreamItem) (string, error) {
	var buf bytes.Buffer
	escapedAction := html.EscapeString(string(stream.Action))
	escapedTarget := html.EscapeString(stream.Target)
	fmt.Fprintf(&buf, `<turbo-stream action="%s" target="%s"><template>`, escapedAction, escapedTarget)
	if stream.Component != nil {
		if err := stream.Component.Render(ctx, &buf); err != nil {
			return "", err
		}
	}
	fmt.Fprint(&buf, `</template></turbo-stream>`)
	return buf.String(), nil
}

// Nonce retrieves the per-request CSP nonce from context if set by SecureHeaders middleware.
// Designed to be called directly from Templ components: `<script nonce={ fullstack.Nonce(c) }></script>`.
func Nonce(c *echo.Context) string {
	if c == nil {
		return ""
	}
	if nonce, ok := c.Get("csp_nonce").(string); ok {
		return nonce
	}
	return ""
}

// CSRFToken retrieves the current CSRF token from the context or cookie.
// Designed to be called from Templ components or handlers.
func CSRFToken(c *echo.Context) string {
	if c == nil {
		return ""
	}
	if token, ok := c.Get("csrf").(string); ok && token != "" {
		return token
	}
	if cookie, err := c.Cookie("_csrf"); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}

// CSRFField renders a hidden HTML input field containing the current CSRF token.
// Designed to be embedded directly inside HTML/Templ forms: `<input type="hidden" name="_csrf" value={ fullstack.CSRFToken(c) }/>`.
func CSRFField(c *echo.Context) string {
	token := CSRFToken(c)
	return fmt.Sprintf(`<input type="hidden" name="_csrf" value="%s" />`, html.EscapeString(token))
}

type csrfContextKey struct{}

// CSRFTokenCtx retrieves the current CSRF token from the Go request context.
// Designed for seamless usage inside Templ components via the component's implicit ctx parameter.
func CSRFTokenCtx(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if token, ok := ctx.Value(csrfContextKey{}).(string); ok {
		return token
	}
	return ""
}

// CSRFFieldCtx renders a hidden HTML input field containing the CSRF token from the context.
func CSRFFieldCtx(ctx context.Context) string {
	token := CSRFTokenCtx(ctx)
	return fmt.Sprintf(`<input type="hidden" name="_csrf" value="%s" />`, html.EscapeString(token))
}


