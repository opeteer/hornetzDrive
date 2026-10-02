package realtime

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v5"
)

// WebSocketConfig defines configuration for WebSocket connections.
type WebSocketConfig struct {
	ReadBufferSize  int
	WriteBufferSize int
	AllowedOrigins  []string
	CheckOrigin     func(r *http.Request) bool
}

// DefaultWebSocketConfig provides secure defaults requiring same-origin verification.
func DefaultWebSocketConfig() WebSocketConfig {
	return WebSocketConfig{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     DefaultCheckOrigin,
	}
}

// DefaultCheckOrigin verifies that the incoming request's Origin header matches its Host header,
// preventing Cross-Site WebSocket Hijacking (CSWSH). Non-browser requests without an Origin header are allowed.
func DefaultCheckOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true // Allow same-origin or non-browser requests
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

// WebSocketHandler upgrades the HTTP connection to a full-duplex WebSocket stream.
// It maps the topic subscription similarly to the SSE Handler, with safe same-origin verification.
func WebSocketHandler(broker EventBroker) echo.HandlerFunc {
	return WebSocketHandlerWithConfig(broker, DefaultWebSocketConfig())
}

// WebSocketHandlerWithConfig upgrades the HTTP connection with custom WebSocket configuration.
func WebSocketHandlerWithConfig(broker EventBroker, cfg WebSocketConfig) echo.HandlerFunc {
	checkOrigin := cfg.CheckOrigin
	if checkOrigin == nil {
		if len(cfg.AllowedOrigins) > 0 {
			checkOrigin = func(r *http.Request) bool {
				origin := r.Header.Get("Origin")
				if origin == "" {
					return true
				}
				u, err := url.Parse(origin)
				if err != nil {
					return false
				}
				if strings.EqualFold(u.Host, r.Host) {
					return true
				}
				for _, allowed := range cfg.AllowedOrigins {
					if strings.EqualFold(u.Host, allowed) || strings.EqualFold(origin, allowed) {
						return true
					}
				}
				return false
			}
		} else {
			checkOrigin = DefaultCheckOrigin
		}
	}

	readBuffer := cfg.ReadBufferSize
	if readBuffer <= 0 {
		readBuffer = 1024
	}
	writeBuffer := cfg.WriteBufferSize
	if writeBuffer <= 0 {
		writeBuffer = 1024
	}

	upgrader := websocket.Upgrader{
		ReadBufferSize:  readBuffer,
		WriteBufferSize: writeBuffer,
		CheckOrigin:     checkOrigin,
	}

	return func(c *echo.Context) error {
		topic := c.QueryParam("topic")
		if topic == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "Missing 'topic' query parameter")
		}

		ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
		if err != nil {
			return err
		}

		ctx := c.Request().Context()
		stream, unsubscribe := broker.Subscribe(ctx, topic)

		defer func() {
			unsubscribe()
			ws.Close()
		}()

		ws.SetReadLimit(maxMessageSize)
		ws.SetReadDeadline(time.Now().Add(pongWait))
		ws.SetPongHandler(func(string) error {
			ws.SetReadDeadline(time.Now().Add(pongWait))
			return nil
		})

		// Read pump to process pong messages and detect disconnects
		go func() {
			defer ws.Close()
			for {
				_, _, err := ws.ReadMessage()
				if err != nil {
					break
				}
			}
		}()

		pingTicker := time.NewTicker(pingPeriod)
		defer pingTicker.Stop()

		for {
			select {
			case msg, ok := <-stream:
				ws.SetWriteDeadline(time.Now().Add(writeWait))
				if !ok {
					ws.WriteMessage(websocket.CloseMessage, []byte{})
					return nil
				}
				if err := ws.WriteMessage(websocket.TextMessage, []byte(msg)); err != nil {
					return nil
				}
			case <-pingTicker.C:
				ws.SetWriteDeadline(time.Now().Add(writeWait))
				if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
					return nil
				}
			case <-ctx.Done():
				return nil
			}
		}
	}
}
