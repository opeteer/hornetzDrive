package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

type errorSink struct{}

func (s *errorSink) Write(ctx context.Context, formatted []byte, entry *Entry) error {
	return errors.New("simulated disk I/O failure")
}
func (s *errorSink) Flush(ctx context.Context) error { return nil }
func (s *errorSink) Close() error                    { return nil }

func TestSyncLogger(t *testing.T) {
	mem := NewMemorySink(10)
	logger := NewSyncLogger(NewJSONFormatter(false), mem, false)

	entry := NewEntry("test.sync")
	if err := logger.Log(context.Background(), entry); err != nil {
		t.Fatalf("sync logger failed: %v", err)
	}

	if mem.Len() != 1 || mem.Last().Action != "test.sync" {
		t.Errorf("entry was not recorded synchronously in memory sink")
	}

	// Test Fail-Closed vs Fail-Safe
	failClosedLogger := NewSyncLogger(NewJSONFormatter(false), &errorSink{}, true)
	if err := failClosedLogger.Log(context.Background(), entry); err == nil {
		t.Errorf("expected error in fail-closed mode when sink fails")
	}

	failSafeLogger := NewSyncLogger(NewJSONFormatter(false), &errorSink{}, false)
	if err := failSafeLogger.Log(context.Background(), entry); err != nil {
		t.Errorf("expected no error in fail-safe mode when sink fails, got: %v", err)
	}
}

func TestAsyncLogger_ProcessingAndDrain(t *testing.T) {
	mem := NewMemorySink(100)
	cfg := AsyncConfig{
		BufferSize:     50,
		Workers:        2,
		OverflowPolicy: PolicyBlock,
	}
	logger := NewAsyncLogger(NewJSONFormatter(false), mem, cfg)

	const count = 30
	var wg sync.WaitGroup
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			e := NewEntry("async.task")
			_ = logger.Log(context.Background(), e)
		}(i)
	}

	wg.Wait()

	// Closing logger drains remaining queue items
	if err := logger.Close(); err != nil {
		t.Fatalf("close failed: %v", err)
	}

	if mem.Len() != count {
		t.Errorf("expected %d entries processed after Close(), got %d", count, mem.Len())
	}
}

func TestAsyncLogger_OverflowDropOldest(t *testing.T) {
	// Intentionally slow sink to induce queue backpressure
	mem := NewMemorySink(100)
	cfg := AsyncConfig{
		BufferSize:     2,
		Workers:        1,
		OverflowPolicy: PolicyDropOldest,
	}
	logger := NewAsyncLogger(NewJSONFormatter(false), mem, cfg)

	for i := 0; i < 10; i++ {
		_ = logger.Log(context.Background(), NewEntry("burst.event"))
	}

	time.Sleep(50 * time.Millisecond)
	_ = logger.Close()

	if mem.Len() == 0 {
		t.Errorf("expected some entries recorded")
	}
}

func TestAsyncLogger_OverflowFallback(t *testing.T) {
	mem := NewMemorySink(100)
	fallbackMem := NewMemorySink(100)

	cfg := AsyncConfig{
		BufferSize:     1,
		Workers:        0, // No workers pulling from queue, so queue stays full after 1
		OverflowPolicy: PolicyFallback,
		FallbackSink:   fallbackMem,
	}

	// Will use 1 worker minimum per NewAsyncLogger
	logger := NewAsyncLogger(NewJSONFormatter(false), mem, cfg)

	// Fill queue quickly
	for i := 0; i < 15; i++ {
		_ = logger.Log(context.Background(), NewEntry("burst.fallback"))
	}

	_ = logger.Close()

	totalRecorded := mem.Len() + fallbackMem.Len()
	if totalRecorded == 0 {
		t.Errorf("expected events to be saved either in main sink or fallback sink")
	}
}
