package realtime

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ztatic-go-framework/fullstack"
)

func TestStress_MemoryBroker_ConcurrencyAndChurn(t *testing.T) {
	broker := NewMemoryBroker()

	// Run stress test for 3 seconds
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var publishedCount int64
	var receivedCount int64

	// 1,000 distinct topics
	topics := make([]string, 1000)
	for i := 0; i < 1000; i++ {
		topics[i] = fmt.Sprintf("topic:%d", i)
	}

	// Spawn 5,000 subscribers with churn and slowloris simulation
	for i := 0; i < 5000; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			topic := topics[id%1000]
			ch, unsub := broker.Subscribe(ctx, topic)

			// 20% are slow readers (Slowloris simulation)
			isSlow := id%5 == 0

			// Churn simulation: disconnect randomly before context ends
			go func() {
				select {
				case <-ctx.Done():
				case <-time.After(time.Duration(id%2000) * time.Millisecond):
					unsub()
				}
			}()

			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
					atomic.AddInt64(&receivedCount, 1)
					if isSlow {
						time.Sleep(10 * time.Millisecond)
					}
				}
			}
		}(i)
	}

	// Spawn 50 aggressive publishers
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Payload scaling: 1KB string
			largePayload := make([]byte, 1024)
			for j := range largePayload {
				largePayload[j] = 'a'
			}

			item := fullstack.TurboStreamItem{
				Action:    fullstack.StreamUpdate,
				Target:    "target",
				Component: MockComponent{Content: string(largePayload)},
			}

			for {
				select {
				case <-ctx.Done():
					return
				default:
					topic := topics[int(atomic.LoadInt64(&publishedCount))%1000]
					_ = broker.Publish(ctx, topic, item)
					atomic.AddInt64(&publishedCount, 1)
					// Sleep briefly to prevent total CPU lockup during local testing
					time.Sleep(time.Microsecond)
				}
			}
		}(i)
	}

	wg.Wait()
	t.Logf("Stress Test Completed. Published: %d, Received: %d", publishedCount, receivedCount)
}
