package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"
)

// Sink represents a destination for formatted audit logs (files, stdout, memory, SIEM).
type Sink interface {
	Write(ctx context.Context, formatted []byte, entry *Entry) error
	Flush(ctx context.Context) error
	Close() error
}

// -----------------------------------------------------------------------------
// WriterSink (io.Writer - Stdout, Stderr, Custom Streams)
// -----------------------------------------------------------------------------

// WriterSink writes formatted audit records to any io.Writer safely across goroutines.
type WriterSink struct {
	mu sync.Mutex
	w  io.Writer
}

// NewWriterSink wraps an arbitrary io.Writer.
func NewWriterSink(w io.Writer) *WriterSink {
	return &WriterSink{w: w}
}

// NewStdoutSink creates a sink targeting standard output.
func NewStdoutSink() *WriterSink {
	return NewWriterSink(os.Stdout)
}

// NewStderrSink creates a sink targeting standard error.
func NewStderrSink() *WriterSink {
	return NewWriterSink(os.Stderr)
}

func (s *WriterSink) Write(ctx context.Context, formatted []byte, entry *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.w.Write(formatted)
	return err
}

func (s *WriterSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if flusher, ok := s.w.(interface{ Flush() error }); ok {
		return flusher.Flush()
	}
	if syncer, ok := s.w.(interface{ Sync() error }); ok {
		return syncer.Sync()
	}
	return nil
}

func (s *WriterSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if closer, ok := s.w.(io.Closer); ok && s.w != os.Stdout && s.w != os.Stderr {
		return closer.Close()
	}
	return nil
}

// -----------------------------------------------------------------------------
// FileSink (Append-Only File with optional fsync durability)
// -----------------------------------------------------------------------------

// FileSink writes audit events to a dedicated log file with 0600 permissions.
type FileSink struct {
	mu          sync.Mutex
	file        *os.File
	syncOnWrite bool
}

// NewFileSink opens or creates an append-only audit file.
func NewFileSink(filePath string, syncOnWrite bool) (*FileSink, error) {
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log file %s: %w", filePath, err)
	}
	return &FileSink{
		file:        file,
		syncOnWrite: syncOnWrite,
	}, nil
}

func (s *FileSink) Write(ctx context.Context, formatted []byte, entry *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.file.Write(formatted); err != nil {
		return err
	}
	if s.syncOnWrite {
		return s.file.Sync()
	}
	return nil
}

func (s *FileSink) Flush(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.file.Sync()
}

func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.file.Sync()
	return s.file.Close()
}

// -----------------------------------------------------------------------------
// MemorySink (Thread-Safe Buffer for Tests and Real-Time Inspection)
// -----------------------------------------------------------------------------

// MemorySink retains recent audit records in memory for programmatic assertions and inspection.
type MemorySink struct {
	mu        sync.RWMutex
	capacity  int
	entries   []*Entry
	formatted [][]byte
}

// NewMemorySink creates a memory sink with an optional capacity limit (0 for unlimited).
func NewMemorySink(capacity int) *MemorySink {
	return &MemorySink{
		capacity:  capacity,
		entries:   make([]*Entry, 0),
		formatted: make([][]byte, 0),
	}
}

func (s *MemorySink) Write(ctx context.Context, formatted []byte, entry *Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Clone formatted slice to prevent mutation
	dataCopy := make([]byte, len(formatted))
	copy(dataCopy, formatted)

	if s.capacity > 0 && len(s.entries) >= s.capacity {
		// Evict oldest item
		s.entries = s.entries[1:]
		s.formatted = s.formatted[1:]
	}

	s.entries = append(s.entries, entry)
	s.formatted = append(s.formatted, dataCopy)
	return nil
}

func (s *MemorySink) Flush(ctx context.Context) error {
	return nil
}

func (s *MemorySink) Close() error {
	return nil
}

// Entries returns a copy of all stored audit entries.
func (s *MemorySink) Entries() []*Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Entry, len(s.entries))
	copy(out, s.entries)
	return out
}

// Last returns the most recently written audit entry, or nil if empty.
func (s *MemorySink) Last() *Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.entries) == 0 {
		return nil
	}
	return s.entries[len(s.entries)-1]
}

// Len returns the current count of stored entries.
func (s *MemorySink) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// RawFormatted returns all formatted byte slices.
func (s *MemorySink) RawFormatted() [][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([][]byte, len(s.formatted))
	copy(out, s.formatted)
	return out
}

// Clear flushes all buffered entries from memory.
func (s *MemorySink) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = s.entries[:0]
	s.formatted = s.formatted[:0]
}

// -----------------------------------------------------------------------------
// MultiSink (Broadcast Fan-Out)
// -----------------------------------------------------------------------------

// MultiSink delivers each audit entry to multiple downstream sinks.
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink constructs a multiplexing sink.
func NewMultiSink(sinks ...Sink) *MultiSink {
	return &MultiSink{sinks: sinks}
}

func (s *MultiSink) Write(ctx context.Context, formatted []byte, entry *Entry) error {
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Write(ctx, formatted, entry); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (s *MultiSink) Flush(ctx context.Context) error {
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Flush(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (s *MultiSink) Close() error {
	var errs []error
	for _, sink := range s.sinks {
		if err := sink.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// -----------------------------------------------------------------------------
// WebhookSink (HTTP POST to Remote SIEM)
// -----------------------------------------------------------------------------

// WebhookSink forwards audit events to remote HTTP endpoints.
type WebhookSink struct {
	endpoint    string
	client      *http.Client
	bearerToken string
	contentType string
}

// NewWebhookSink constructs an HTTP webhook audit sink.
func NewWebhookSink(endpoint string, client *http.Client, bearerToken string) *WebhookSink {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	return &WebhookSink{
		endpoint:    endpoint,
		client:      client,
		bearerToken: bearerToken,
		contentType: "application/json",
	}
}

func (s *WebhookSink) SetContentType(ct string) {
	s.contentType = ct
}

func (s *WebhookSink) Write(ctx context.Context, formatted []byte, entry *Entry) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(formatted))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", s.contentType)
	req.Header.Set("User-Agent", "Ztatic-Audit-Webhook/1.0")
	if s.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.bearerToken)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("audit webhook POST failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("audit webhook returned HTTP status %d", resp.StatusCode)
	}
	return nil
}

func (s *WebhookSink) Flush(ctx context.Context) error {
	return nil
}

func (s *WebhookSink) Close() error {
	return nil
}
