package realtime

import (
	"context"

	"github.com/redis/go-redis/v9"
	"ztatic-go-framework/fullstack"
)

// RedisBroker implements the EventBroker interface using Redis Pub/Sub,
// enabling horizontal scaling across multiple Ztatic server instances.
type RedisBroker struct {
	rdb redis.UniversalClient
}

// NewRedisBroker creates a new distributed broker using a Redis client.
func NewRedisBroker(rdb redis.UniversalClient) *RedisBroker {
	return &RedisBroker{
		rdb: rdb,
	}
}

// Subscribe returns a read-only channel that receives HTML stream updates for the specified topic,
// along with a cleanup function to unsubscribe.
func (r *RedisBroker) Subscribe(ctx context.Context, topic string) (<-chan string, func()) {
	if topic == "" {
		ch := make(chan string)
		close(ch)
		return ch, func() {}
	}

	pubsub := r.rdb.Subscribe(ctx, topic)
	ch := make(chan string, 64)

	go func() {
		redisCh := pubsub.Channel()
		for msg := range redisCh {
			select {
			case ch <- msg.Payload:
			default:
				// Buffer full; skip to prevent blocking
			}
		}
		close(ch)
	}()

	unsubscribe := func() {
		pubsub.Close()
	}

	return ch, unsubscribe
}

// Publish formats a Turbo Stream fragment and broadcasts it to the Redis topic.
func (r *RedisBroker) Publish(ctx context.Context, topic string, item fullstack.TurboStreamItem) error {
	if topic == "" {
		return ErrTopicEmpty
	}

	// Render Templ Component into a raw Turbo Stream HTML string
	htmlFragment, err := fullstack.RenderStreamToString(ctx, item)
	if err != nil {
		return err
	}

	return r.rdb.Publish(ctx, topic, htmlFragment).Err()
}
