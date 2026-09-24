package realtime

import (
	"context"
	"errors"
	"sync"

	"ztatic-go-framework/fullstack"
)

var (
	ErrTopicEmpty = errors.New("ztatic/realtime: topic cannot be empty")
)

// EventBroker defines the contract for real-time pub/sub messaging.
type EventBroker interface {
	Subscribe(ctx context.Context, topic string) (<-chan string, func())
	Publish(ctx context.Context, topic string, item fullstack.TurboStreamItem) error
}

// MemoryBroker implements an in-memory, thread-safe Pub/Sub broker for single-instance applications.
type MemoryBroker struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan string]struct{}
}

// NewMemoryBroker creates a new local event broker.
func NewMemoryBroker() *MemoryBroker {
	return &MemoryBroker{
		subscribers: make(map[string]map[chan string]struct{}),
	}
}

// Subscribe returns a read-only channel that receives HTML stream updates for the specified topic,
// along with a cleanup function to unsubscribe when the client disconnects.
func (b *MemoryBroker) Subscribe(ctx context.Context, topic string) (<-chan string, func()) {
	if topic == "" {
		// Return dummy channel for empty topics
		ch := make(chan string)
		close(ch)
		return ch, func() {}
	}

	ch := make(chan string, 64) // buffer to prevent blocking publishers

	b.mu.Lock()
	if _, ok := b.subscribers[topic]; !ok {
		b.subscribers[topic] = make(map[chan string]struct{})
	}
	b.subscribers[topic][ch] = struct{}{}
	b.mu.Unlock()

	unsubscribe := func() {
		b.mu.Lock()
		defer b.mu.Unlock()

		if subs, ok := b.subscribers[topic]; ok {
			if _, exists := subs[ch]; exists {
				delete(subs, ch)
			}
			// Clean up empty topic maps
			if len(subs) == 0 {
				delete(b.subscribers, topic)
			}
		}
	}

	return ch, unsubscribe
}

// Publish formats a Turbo Stream fragment and broadcasts it to all active subscribers on the topic.
func (b *MemoryBroker) Publish(ctx context.Context, topic string, item fullstack.TurboStreamItem) error {
	if topic == "" {
		return ErrTopicEmpty
	}

	// 1. Render Templ Component into a raw Turbo Stream HTML string
	htmlFragment, err := fullstack.RenderStreamToString(ctx, item)
	if err != nil {
		return err
	}

	b.mu.RLock()
	subs, ok := b.subscribers[topic]
	if !ok || len(subs) == 0 {
		b.mu.RUnlock()
		return nil // Nobody is listening
	}

	// Snapshot active channels to avoid holding lock during send
	channels := make([]chan string, 0, len(subs))
	for ch := range subs {
		channels = append(channels, ch)
	}
	b.mu.RUnlock()

	// 2. Broadcast to all active channels
	for _, ch := range channels {
		select {
		case ch <- htmlFragment:
			// Message sent successfully
		default:
			// Subscriber is too slow (buffer full), skip to avoid blocking other subscribers.
			// In a robust production system, you might forcefully disconnect slow clients here.
		}
	}

	return nil
}
