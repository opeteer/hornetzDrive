package data

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBreakpoint_DBEngine_Contention(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	// Severe Pool Restriction: Max 2 connections
	db.SQL.SetMaxOpenConns(2)

	goroutineTiers := []int{100, 1000, 5000, 20000}

	for _, tier := range goroutineTiers {
		t.Logf("=== DB Breakpoint Tier: %d Parallel Goroutines (MaxConns=2) ===", tier)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		var wg sync.WaitGroup
		var successCount int64
		var timeoutCount int64

		for i := 0; i < tier; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := db.Transaction(ctx, func(tx *sql.Tx) error {
					time.Sleep(1 * time.Millisecond)
					return nil
				})

				if err != nil {
					atomic.AddInt64(&timeoutCount, 1)
				} else {
					atomic.AddInt64(&successCount, 1)
				}
			}()
		}

		wg.Wait()
		cancel()

		failureRate := float64(timeoutCount) / float64(tier) * 100
		t.Logf("Tier %d: Successes=%d, Timeouts=%d, FailureRate=%.2f%%", tier, successCount, timeoutCount, failureRate)

		if failureRate > 90.0 {
			t.Logf("💥 DB BREAKING POINT REACHED AT %d GOROUTINES! Pool lockup failure rate: %.2f%%", tier, failureRate)
			break
		}
	}
}
