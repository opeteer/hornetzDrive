package data

import (
	"context"
	"database/sql"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestStress_DatabaseContentionAndChaos(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	var wg sync.WaitGroup
	var successCount int64
	var rollbackCount int64
	var panicRecoveryCount int64
	var timeoutCount int64

	// Stress Test: 500 parallel transactions
	for i := 0; i < 500; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Context cancellation 15% of the time (1ms timeout)
			timeout := 10 * time.Millisecond
			if id%7 == 0 {
				timeout = 1 * time.Microsecond // Trigger context timeout
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			defer func() {
				if p := recover(); p != nil {
					atomic.AddInt64(&panicRecoveryCount, 1)
				}
			}()

			err := db.Transaction(ctx, func(tx *sql.Tx) error {
				// Artificial panic injection 20% of the time
				if id%5 == 0 {
					panic("simulated chaos panic")
				}

				// Simulate database work
				time.Sleep(1 * time.Millisecond)

				if ctx.Err() != nil {
					return ctx.Err() // Propagate timeout
				}
				return nil
			})

			if err != nil {
				if err == context.DeadlineExceeded {
					atomic.AddInt64(&timeoutCount, 1)
				} else {
					atomic.AddInt64(&rollbackCount, 1)
				}
			} else {
				atomic.AddInt64(&successCount, 1)
			}
		}(i)
	}

	wg.Wait()
	t.Logf("DB Stress Completed. Success: %d, Panics: %d, Timeouts: %d, Errors: %d",
		successCount, panicRecoveryCount, timeoutCount, rollbackCount)
}
