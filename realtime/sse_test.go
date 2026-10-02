package realtime

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/fullstack"
)

func TestSSEHandler_MissingTopic(t *testing.T) {
	broker := NewMemoryBroker()
	e := echo.New()
	e.GET("/sse", SSEHandler(broker))

	req := httptest.NewRequest(http.MethodGet, "/sse", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected HTTP 400 Bad Request when topic is missing, got %d", rec.Code)
	}
}

func TestSSEHandler_StreamDelivery(t *testing.T) {
	broker := NewMemoryBroker()
	e := echo.New()
	e.GET("/sse", SSEHandler(broker))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/sse?topic=test-room", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		e.ServeHTTP(rec, req)
		close(done)
	}()

	// Wait briefly for connection setup
	time.Sleep(50 * time.Millisecond)

	// Publish message to topic
	item := fullstack.TurboStreamItem{
		Action: fullstack.StreamAppend,
		Target: "chat",
	}
	publishErr := broker.Publish(context.Background(), "test-room", item)
	if publishErr != nil {
		t.Fatalf("failed to publish to broker: %v", publishErr)
	}

	time.Sleep(50 * time.Millisecond)

	// Cancel context to end stream loop
	cancel()
	<-done

	// Verify SSE headers
	if rec.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("expected Content-Type text/event-stream, got %q", rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "no-cache" {
		t.Errorf("expected Cache-Control no-cache")
	}

	body := rec.Body.String()
	if !strings.Contains(body, "event: message") || !strings.Contains(body, "turbo-stream action=\"append\" target=\"chat\"") {
		t.Errorf("expected SSE body to contain event: message and turbo-stream action=\"append\", got %q", body)
	}
}
