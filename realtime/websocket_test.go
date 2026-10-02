package realtime

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/labstack/echo/v5"
	"ztatic-go-framework/fullstack"
)

type dummyComponent struct{}

func (d dummyComponent) Render(ctx context.Context, w io.Writer) error {
	w.Write([]byte("<div>hello</div>"))
	return nil
}

func TestWebSocketHandler(t *testing.T) {
	e := echo.New()
	broker := NewMemoryBroker()
	
	e.GET("/ws", WebSocketHandler(broker))
	server := httptest.NewServer(e)
	defer server.Close()

	// Convert http:// to ws://
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws?topic=testroom"

	dialer := websocket.Dialer{}
	conn, resp, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial websocket: %v", err)
	}
	defer conn.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("Expected 101 Switching Protocols, got %d", resp.StatusCode)
	}

	// Publish message
	err = broker.Publish(context.Background(), "testroom", fullstack.TurboStreamItem{
		Action:    fullstack.StreamAppend,
		Target:    "chat",
		Component: dummyComponent{},
	})
	if err != nil {
		t.Fatalf("Failed to publish: %v", err)
	}

	// Read message from websocket
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	messageType, p, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("Failed to read message: %v", err)
	}

	if messageType != websocket.TextMessage {
		t.Fatalf("Expected text message, got %d", messageType)
	}

	msgStr := string(p)
	if !strings.Contains(msgStr, `<turbo-stream action="append" target="chat">`) {
		t.Errorf("Unexpected message format: %s", msgStr)
	}
	if !strings.Contains(msgStr, `<div>hello</div>`) {
		t.Errorf("Missing component HTML: %s", msgStr)
	}
}

func TestWebSocketHandler_MissingTopic(t *testing.T) {
	e := echo.New()
	broker := NewMemoryBroker()
	
	e.GET("/ws", WebSocketHandler(broker))
	server := httptest.NewServer(e)
	defer server.Close()

	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"

	dialer := websocket.Dialer{}
	_, resp, err := dialer.Dial(wsURL, nil)
	if err == nil {
		t.Fatal("Expected error when connecting without topic, but got nil")
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected 400 Bad Request, got %d", resp.StatusCode)
	}
}
