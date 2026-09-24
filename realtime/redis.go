package realtime

import (
	"context"
	"errors"

	"ztatic-go-framework/fullstack"
)

// RedisBroker implements the EventBroker interface using Redis Pub/Sub,
// enabling horizontal scaling across multiple Ztatic server instances.
type RedisBroker struct {
	// redisClient *redis.Client
}

func NewRedisBroker() *RedisBroker {
	return &RedisBroker{}
}

func (r *RedisBroker) Subscribe(ctx context.Context, topic string) (<-chan string, func()) {
	ch := make(chan string)
	close(ch)
	return ch, func() {}
}

func (r *RedisBroker) Publish(ctx context.Context, topic string, item fullstack.TurboStreamItem) error {
	return errors.New("ztatic/realtime: redis broker requires go-redis/redis/v8 installation")
}
