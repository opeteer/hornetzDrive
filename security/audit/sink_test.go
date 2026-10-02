package audit

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterSink(t *testing.T) {
	var buf bytes.Buffer
	sink := NewWriterSink(&buf)
	entry := NewEntry("test.event")

	data := []byte("audit payload line\n")
	if err := sink.Write(context.Background(), data, entry); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	if buf.String() != "audit payload line\n" {
		t.Errorf("unexpected buffer content: %s", buf.String())
	}
}

func TestFileSink(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	sink, err := NewFileSink(logPath, true)
	if err != nil {
		t.Fatalf("failed to create FileSink: %v", err)
	}
	defer sink.Close()

	entry := NewEntry("file.write")
	data := []byte("file log line\n")

	if err := sink.Write(context.Background(), data, entry); err != nil {
		t.Fatalf("failed to write to FileSink: %v", err)
	}

	_ = sink.Flush(context.Background())

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if string(content) != "file log line\n" {
		t.Errorf("unexpected file content: %s", string(content))
	}

	// Verify permissions (0600)
	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("failed to stat file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("expected permissions 0600, got %o", perm)
	}
}

func TestMemorySink(t *testing.T) {
	sink := NewMemorySink(2) // capacity 2
	ctx := context.Background()

	e1 := NewEntry("event.1")
	e2 := NewEntry("event.2")
	e3 := NewEntry("event.3")

	_ = sink.Write(ctx, []byte("1"), e1)
	_ = sink.Write(ctx, []byte("2"), e2)

	if sink.Len() != 2 {
		t.Errorf("expected len 2, got %d", sink.Len())
	}
	if sink.Last().Action != "event.2" {
		t.Errorf("expected last event to be event.2, got %s", sink.Last().Action)
	}

	// Exceed capacity -> event.1 should be evicted
	_ = sink.Write(ctx, []byte("3"), e3)

	if sink.Len() != 2 {
		t.Errorf("expected len 2 after eviction, got %d", sink.Len())
	}
	entries := sink.Entries()
	if entries[0].Action != "event.2" || entries[1].Action != "event.3" {
		t.Errorf("unexpected entries after eviction: %s, %s", entries[0].Action, entries[1].Action)
	}

	sink.Clear()
	if sink.Len() != 0 || sink.Last() != nil {
		t.Errorf("sink not cleared properly")
	}
}

func TestMultiSink(t *testing.T) {
	var buf1 bytes.Buffer
	var buf2 bytes.Buffer

	s1 := NewWriterSink(&buf1)
	s2 := NewWriterSink(&buf2)
	multi := NewMultiSink(s1, s2)

	entry := NewEntry("multi.test")
	payload := []byte("broadcasted line\n")

	if err := multi.Write(context.Background(), payload, entry); err != nil {
		t.Fatalf("multi sink write failed: %v", err)
	}

	if buf1.String() != "broadcasted line\n" || buf2.String() != "broadcasted line\n" {
		t.Errorf("multi sink failed to write to both destinations")
	}
}

func TestWebhookSink(t *testing.T) {
	var receivedBody string
	var receivedAuth string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		bodyBytes, _ := io.ReadAll(r.Body)
		receivedBody = string(bodyBytes)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	sink := NewWebhookSink(server.URL, server.Client(), "test-token-123")
	entry := NewEntry("webhook.event")
	payload := []byte(`{"event":"test"}`)

	if err := sink.Write(context.Background(), payload, entry); err != nil {
		t.Fatalf("webhook sink write failed: %v", err)
	}

	if receivedBody != `{"event":"test"}` {
		t.Errorf("unexpected webhook payload: %s", receivedBody)
	}
	if !strings.Contains(receivedAuth, "Bearer test-token-123") {
		t.Errorf("unexpected auth header: %s", receivedAuth)
	}
}
