package realtime

import (
	"context"
	"io"
	"sync"
	"testing"
	"time"

	"ztatic-go-framework/fullstack"
)

// MockComponent implements the Component shim for testing
type MockComponent struct {
	Content string
}

func (m MockComponent) Render(ctx context.Context, w io.Writer) error {
	_, err := w.Write([]byte(m.Content))
	return err
}

func TestMemoryBroker_SubscribeAndPublish(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()

	// 1. Subscribe to a topic
	ch, unsubscribe := broker.Subscribe(ctx, "room:101")
	defer unsubscribe()

	// 2. Publish a message to the topic
	item := fullstack.TurboStreamItem{
		Action:    fullstack.StreamAppend,
		Target:    "messages",
		Component: MockComponent{Content: "<div>Hello</div>"},
	}
	err := broker.Publish(ctx, "room:101", item)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}

	// 3. Receive the formatted Turbo Stream HTML
	select {
	case msg := <-ch:
		expected := `<turbo-stream action="append" target="messages"><template><div>Hello</div></template></turbo-stream>`
		if msg != expected {
			t.Errorf("Expected\n%s\nGot\n%s", expected, msg)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Timeout waiting for message on subscribed channel")
	}
}

func TestMemoryBroker_Unsubscribe(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()

	_, unsubscribe := broker.Subscribe(ctx, "room:101")

	// Unsubscribe immediately
	unsubscribe()

	// Verify internal map cleanup
	broker.mu.RLock()
	defer broker.mu.RUnlock()
	if _, ok := broker.subscribers["room:101"]; ok {
		t.Fatal("Expected topic to be deleted from subscribers map after last client disconnected")
	}
}

func TestMemoryBroker_Concurrency(t *testing.T) {
	broker := NewMemoryBroker()
	ctx := context.Background()
	var wg sync.WaitGroup

	// Spawn 100 concurrent publishers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			item := fullstack.TurboStreamItem{
				Action:    fullstack.StreamUpdate,
				Target:    "status",
				Component: MockComponent{Content: "ok"},
			}
			broker.Publish(ctx, "room:101", item)
		}(i)
	}

	// Spawn 100 concurrent subscribers
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, unsub := broker.Subscribe(ctx, "room:101")
			time.Sleep(10 * time.Millisecond)
			unsub()
		}()
	}

	wg.Wait()
	// If it doesn't panic or data race, test passes.
}
