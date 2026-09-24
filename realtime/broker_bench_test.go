package realtime

import (
	"context"
	"testing"
	"ztatic-go-framework/fullstack"
)

// BenchmarkMemoryBroker tests the throughput of publishing Turbo Streams to many subscribers.
func BenchmarkMemoryBroker_Publish(b *testing.B) {
	broker := NewMemoryBroker()
	ctx := context.Background()

	// Setup 100 subscribers
	for i := 0; i < 100; i++ {
		_, unsub := broker.Subscribe(ctx, "benchmark:room")
		defer unsub()
	}

	item := fullstack.TurboStreamItem{
		Action:    fullstack.StreamUpdate,
		Target:    "status",
		Component: MockComponent{Content: "benchmark_test"},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = broker.Publish(ctx, "benchmark:room", item)
	}
}
