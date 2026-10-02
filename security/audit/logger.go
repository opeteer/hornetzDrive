package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

// Logger defines the core audit recording interface.
type Logger interface {
	Log(ctx context.Context, entry *Entry) error
	Close() error
}

// -----------------------------------------------------------------------------
// Synchronous Logger (Fail-Closed & Direct Writing)
// -----------------------------------------------------------------------------

// SyncLogger records audit events immediately on the calling goroutine.
type SyncLogger struct {
	formatter  Formatter
	sink       Sink
	failClosed bool
}

// NewSyncLogger constructs a synchronous audit logger.
func NewSyncLogger(formatter Formatter, sink Sink, failClosed bool) *SyncLogger {
	if formatter == nil {
		formatter = NewJSONFormatter(false)
	}
	if sink == nil {
		sink = NewStdoutSink()
	}
	return &SyncLogger{
		formatter:  formatter,
		sink:       sink,
		failClosed: failClosed,
	}
}

func (l *SyncLogger) Log(ctx context.Context, entry *Entry) error {
	formatted, err := l.formatter.Format(entry)
	if err != nil {
		if l.failClosed {
			return fmt.Errorf("audit format error: %w", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "[ZTATIC AUDIT ERROR] format error: %v\n", err)
		return nil
	}

	if err := l.sink.Write(ctx, formatted, entry); err != nil {
		if l.failClosed {
			return fmt.Errorf("audit write error: %w", err)
		}
		_, _ = fmt.Fprintf(os.Stderr, "[ZTATIC AUDIT ERROR] write error: %v\n", err)
		return nil
	}

	return nil
}

func (l *SyncLogger) Close() error {
	_ = l.sink.Flush(context.Background())
	return l.sink.Close()
}

// -----------------------------------------------------------------------------
// Asynchronous Logger (Non-Blocking Channel Worker Pool)
// -----------------------------------------------------------------------------

// OverflowPolicy dictates how to handle full buffer queues under extreme load.
type OverflowPolicy string

const (
	// PolicyDropOldest discards the oldest unconsumed audit event in the queue.
	PolicyDropOldest OverflowPolicy = "drop_oldest"
	// PolicyBlock pauses the caller until queue capacity is available (preserves every record).
	PolicyBlock OverflowPolicy = "block"
	// PolicyFallback writes the event immediately to an emergency fallback sink (e.g., stderr).
	PolicyFallback OverflowPolicy = "fallback"
)

// AsyncConfig configures the AsyncLogger worker queue.
type AsyncConfig struct {
	BufferSize     int
	Workers        int
	OverflowPolicy OverflowPolicy
	FallbackSink   Sink
}

// DefaultAsyncConfig provides robust defaults for production workloads.
func DefaultAsyncConfig() AsyncConfig {
	return AsyncConfig{
		BufferSize:     2048,
		Workers:        2,
		OverflowPolicy: PolicyFallback,
		FallbackSink:   NewStderrSink(),
	}
}

// AsyncLogger queues audit records into a non-blocking channel processed by background workers.
type AsyncLogger struct {
	formatter    Formatter
	sink         Sink
	fallbackSink Sink
	policy       OverflowPolicy
	queue        chan *Entry
	wg           sync.WaitGroup
	closed       bool
	closeMu      sync.RWMutex
}

// NewAsyncLogger starts an asynchronous background audit worker pool.
func NewAsyncLogger(formatter Formatter, sink Sink, cfg AsyncConfig) *AsyncLogger {
	if formatter == nil {
		formatter = NewJSONFormatter(false)
	}
	if sink == nil {
		sink = NewStdoutSink()
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = 2048
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	if cfg.OverflowPolicy == "" {
		cfg.OverflowPolicy = PolicyFallback
	}
	if cfg.FallbackSink == nil {
		cfg.FallbackSink = NewStderrSink()
	}

	l := &AsyncLogger{
		formatter:    formatter,
		sink:         sink,
		fallbackSink: cfg.FallbackSink,
		policy:       cfg.OverflowPolicy,
		queue:        make(chan *Entry, cfg.BufferSize),
	}

	// Spawn background workers
	for i := 0; i < cfg.Workers; i++ {
		l.wg.Add(1)
		go l.worker()
	}

	return l
}

func (l *AsyncLogger) worker() {
	defer l.wg.Done()
	ctx := context.Background()

	for entry := range l.queue {
		formatted, err := l.formatter.Format(entry)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[ZTATIC AUDIT WORKER] format error: %v\n", err)
			continue
		}

		if err := l.sink.Write(ctx, formatted, entry); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "[ZTATIC AUDIT WORKER] sink error: %v, routing to fallback\n", err)
			if l.fallbackSink != nil {
				_ = l.fallbackSink.Write(ctx, formatted, entry)
			}
		}
	}
}

func (l *AsyncLogger) Log(ctx context.Context, entry *Entry) error {
	l.closeMu.RLock()
	if l.closed {
		l.closeMu.RUnlock()
		return errors.New("audit logger is closed")
	}
	l.closeMu.RUnlock()

	// Clone to detach from request lifecycle
	entryCopy := entry.Clone()

	switch l.policy {
	case PolicyBlock:
		select {
		case l.queue <- entryCopy:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}

	case PolicyDropOldest:
		for {
			select {
			case l.queue <- entryCopy:
				return nil
			default:
				// Channel is full, evict one item
				select {
				case <-l.queue:
				default:
				}
			}
		}

	case PolicyFallback:
		fallthrough
	default:
		select {
		case l.queue <- entryCopy:
			return nil
		default:
			// Queue is full, write directly to emergency fallback
			if l.fallbackSink != nil {
				formatted, err := l.formatter.Format(entryCopy)
				if err == nil {
					return l.fallbackSink.Write(ctx, formatted, entryCopy)
				}
			}
			return nil
		}
	}
}

// Close gracefully drains remaining items in the queue and terminates workers.
func (l *AsyncLogger) Close() error {
	l.closeMu.Lock()
	if l.closed {
		l.closeMu.Unlock()
		return nil
	}
	l.closed = true
	close(l.queue)
	l.closeMu.Unlock()

	// Wait for workers to drain the queue
	l.wg.Wait()

	// Flush and close sinks
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = l.sink.Flush(ctx)
	err := l.sink.Close()
	if l.fallbackSink != nil {
		_ = l.fallbackSink.Close()
	}
	return err
}
