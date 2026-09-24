package realtime

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"ztatic-go-framework/fullstack"
)

type BreakpointResult struct {
	Tier              int
	Subscribers       int
	Publishers        int
	PayloadSize       int
	ActiveGoroutines  int
	AllocatedMB       float64
	PublishedMessages int64
	ReceivedMessages  int64
	Status            string
	ErrorReason       string
}

func TestBreakpoint_RealtimeBroker_Escalation(t *testing.T) {
	tiers := []struct {
		Subscribers int
		Publishers  int
		PayloadKB   int
	}{
		{Subscribers: 1000, Publishers: 10, PayloadKB: 1},
		{Subscribers: 5000, Publishers: 50, PayloadKB: 10},
		{Subscribers: 20000, Publishers: 100, PayloadKB: 50},
		{Subscribers: 50000, Publishers: 200, PayloadKB: 100},
		{Subscribers: 100000, Publishers: 500, PayloadKB: 250}, // Expected to break or hit resource limits
	}

	results := make([]BreakpointResult, 0)

	for i, tier := range tiers {
		t.Logf("=== Starting Escalation Tier %d: Subs=%d, Pubs=%d, Payload=%dKB ===",
			i+1, tier.Subscribers, tier.Publishers, tier.PayloadKB)

		res := runTier(t, i+1, tier.Subscribers, tier.Publishers, tier.PayloadKB)
		results = append(results, res)

		t.Logf("Tier %d Result: Status=%s, Goroutines=%d, AllocMB=%.2f, Pubs=%d, Recvs=%d, Err=%s",
			res.Tier, res.Status, res.ActiveGoroutines, res.AllocatedMB, res.PublishedMessages, res.ReceivedMessages, res.ErrorReason)

		if res.Status == "BROKEN" {
			t.Logf("💥 BREAKING POINT REACHED AT TIER %d!", i+1)
			break
		}

		// Force GC cleanup between tiers to reset baseline
		runtime.GC()
		time.Sleep(100 * time.Millisecond)
	}

	t.Logf("=== Final Break-Point Summary ===")
	for _, r := range results {
		t.Logf("Tier %d [%s]: Subs=%d, Mem=%.2fMB, Err=%s", r.Tier, r.Status, r.Subscribers, r.AllocatedMB, r.ErrorReason)
	}
}

func runTier(t *testing.T, tierNum, numSubs, numPubs, payloadKB int) BreakpointResult {
	broker := NewMemoryBroker()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var published int64
	var received int64

	payload := make([]byte, payloadKB*1024)
	for i := range payload {
		payload[i] = 'X'
	}
	item := fullstack.TurboStreamItem{
		Action:    fullstack.StreamUpdate,
		Target:    "dest",
		Component: MockComponent{Content: string(payload)},
	}

	// Spawn Subscribers
	for i := 0; i < numSubs; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			topic := fmt.Sprintf("topic:%d", id%500)
			ch, unsub := broker.Subscribe(ctx, topic)
			defer unsub()

			for {
				select {
				case <-ctx.Done():
					return
				case _, ok := <-ch:
					if !ok {
						return
					}
					atomic.AddInt64(&received, 1)
				}
			}
		}(i)
	}

	// Spawn Publishers
	for i := 0; i < numPubs; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					topic := fmt.Sprintf("topic:%d", (id+int(atomic.LoadInt64(&published)))%500)
					err := broker.Publish(ctx, topic, item)
					if err != nil {
						return
					}
					atomic.AddInt64(&published, 1)
					time.Sleep(100 * time.Microsecond)
				}
			}
		}(i)
	}

	wg.Wait()

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	res := BreakpointResult{
		Tier:              tierNum,
		Subscribers:       numSubs,
		Publishers:        numPubs,
		PayloadSize:       payloadKB * 1024,
		ActiveGoroutines:  runtime.NumGoroutine(),
		AllocatedMB:       float64(memStats.Alloc) / (1024 * 1024),
		PublishedMessages: published,
		ReceivedMessages:  received,
		Status:            "PASSED",
	}

	// Define breaking condition threshold for tier test
	if res.AllocatedMB > 800 { // 800MB allocation limit threshold for break-point
		res.Status = "BROKEN"
		res.ErrorReason = fmt.Sprintf("Memory limit threshold exceeded: %.2f MB", res.AllocatedMB)
	} else if published == 0 {
		res.Status = "BROKEN"
		res.ErrorReason = "Publisher starvation"
	}

	return res
}
