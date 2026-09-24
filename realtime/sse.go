package realtime

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v5"
)

// SSEHandler creates an HTTP endpoint that streams Turbo Stream events to the browser.
// The client connects natively via Hotwire Turbo 8: `<turbo-stream-from src="/sse?topic=room:101">`.
// Zero custom client-side JavaScript is required.
func SSEHandler(broker EventBroker) echo.HandlerFunc {
	return func(c *echo.Context) error {
		topic := c.QueryParam("topic")
		if topic == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "Missing 'topic' query parameter")
		}

		// Configure strict headers for Server-Sent Events
		res := c.Response()
		res.Header().Set("Content-Type", "text/event-stream")
		res.Header().Set("Cache-Control", "no-cache")
		res.Header().Set("Connection", "keep-alive")

		// Disable proxy buffering for Nginx to ensure real-time packet delivery
		res.Header().Set("X-Accel-Buffering", "no")

		// Flush headers to establish the streaming connection immediately
		if flusher, ok := res.(http.Flusher); ok {
			flusher.Flush()
		}

		// Subscribe to the topic broker
		ctx := c.Request().Context()
		stream, unsubscribe := broker.Subscribe(ctx, topic)

		// Ensure cleanup when the HTTP request ends (client disconnects)
		defer unsubscribe()

		// Keep-alive Streaming Loop
		for {
			select {
			case <-ctx.Done():
				// Client disconnected (e.g., closed browser tab or navigated away)
				return nil
			case msg, ok := <-stream:
				if !ok {
					// Stream closed by broker
					return nil
				}

				// W3C EventSource Format for Turbo Streams
				// The native Turbo `<turbo-stream-from>` element listens for standard "message" events
				// containing `<turbo-stream>` HTML in the data payload.
				_, err := fmt.Fprintf(res, "event: message\ndata: %s\n\n", msg)
				if err != nil {
					// Write error, client likely disconnected
					return nil
				}

				// Push the buffer to the client immediately
				if flusher, ok := res.(http.Flusher); ok {
					flusher.Flush()
				}
			}
		}
	}
}
