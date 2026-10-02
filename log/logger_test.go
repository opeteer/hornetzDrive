package log

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestJSONHandler_Formatting(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: false,
	}
	logger := New(cfg)

	logger.Info("user logged in", "user_id", "u_123", "attempts", 1)

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON, got error: %v, raw: %s", err, buf.String())
	}

	if logged["msg"] != "user logged in" {
		t.Errorf("expected msg 'user logged in', got %v", logged["msg"])
	}
	if logged["level"] != "INFO" {
		t.Errorf("expected level 'INFO', got %v", logged["level"])
	}
	if logged["user_id"] != "u_123" {
		t.Errorf("expected user_id 'u_123', got %v", logged["user_id"])
	}
	if logged["attempts"] != float64(1) {
		t.Errorf("expected attempts 1, got %v", logged["attempts"])
	}
}

func TestConsoleHandler_ColorAndPlain(t *testing.T) {
	var buf bytes.Buffer
	handler := NewConsoleHandler(&buf, &ConsoleHandlerOptions{
		Level:      LevelDebug,
		NoColor:    true,
		TimeFormat: "15:04:05",
	})
	logger := slog.New(handler)

	logger.Debug("debugging service", "component", "cache", "hits", 42)

	output := buf.String()
	if !strings.Contains(output, "[DEBUG]") {
		t.Errorf("expected [DEBUG] in output, got: %s", output)
	}
	if !strings.Contains(output, "debugging service") {
		t.Errorf("expected message in output, got: %s", output)
	}
	if !strings.Contains(output, "component=cache") || !strings.Contains(output, "hits=42") {
		t.Errorf("expected attributes in output, got: %s", output)
	}
}

func TestDynamicLevelSwitching(t *testing.T) {
	var buf bytes.Buffer
	lvlVar := new(slog.LevelVar)
	lvlVar.Set(LevelInfo)

	cfg := Config{
		LevelVar: lvlVar,
		Format:   FormatJSON,
		Output:   &buf,
	}
	logger := New(cfg)

	// In INFO mode, DEBUG should not be emitted
	logger.Debug("this debug log should be suppressed")
	if buf.Len() != 0 {
		t.Fatalf("expected 0 bytes logged for DEBUG when level is INFO, got: %s", buf.String())
	}

	// Dynamically bump to DEBUG at runtime
	lvlVar.Set(LevelDebug)
	logger.Debug("this debug log should now appear")
	if !strings.Contains(buf.String(), "this debug log should now appear") {
		t.Fatalf("expected debug message after dynamic level bump, got: %s", buf.String())
	}

	// Dynamically switch to ERROR
	buf.Reset()
	lvlVar.Set(LevelError)
	logger.Info("info log should now be suppressed")
	if buf.Len() != 0 {
		t.Fatalf("expected 0 bytes logged for INFO when level is ERROR, got: %s", buf.String())
	}

	logger.Error("critical system fault")
	if !strings.Contains(buf.String(), "critical system fault") {
		t.Fatalf("expected error message when level is ERROR, got: %s", buf.String())
	}
}

func TestContextHandler_CorrelationExtraction(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: &buf,
	}
	logger := New(cfg)

	ctx := context.Background()
	ctx = context.WithValue(ctx, ContextKeyRequestID, "req-xyz-789")
	ctx = context.WithValue(ctx, ContextKeyTraceID, "trace-abc-123")
	ctx = context.WithValue(ctx, ContextKeyUserID, "usr-999")

	logger.InfoContext(ctx, "processing order", "order_id", "ord_555")

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON, got: %v", err)
	}

	if logged["req_id"] != "req-xyz-789" {
		t.Errorf("expected req_id 'req-xyz-789', got %v", logged["req_id"])
	}
	if logged["trace_id"] != "trace-abc-123" {
		t.Errorf("expected trace_id 'trace-abc-123', got %v", logged["trace_id"])
	}
	if logged["user_id"] != "usr-999" {
		t.Errorf("expected user_id 'usr-999', got %v", logged["user_id"])
	}
	if logged["order_id"] != "ord_555" {
		t.Errorf("expected order_id 'ord_555', got %v", logged["order_id"])
	}
}

func TestPrivacyMasking_Scrubbing(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: true,
	}
	logger := New(cfg)

	logger.Info("authenticating user",
		"username", "alice",
		"password", "SuperSecret123!",
		"api_key", "sk_live_xyz",
		"token", "bearer.jwt.token",
	)

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON, got: %v", err)
	}

	if logged["username"] != "alice" {
		t.Errorf("expected username 'alice' to remain unmasked, got %v", logged["username"])
	}
	if logged["password"] != "[REDACTED]" {
		t.Errorf("expected password to be [REDACTED], got %v", logged["password"])
	}
	if logged["api_key"] != "[REDACTED]" {
		t.Errorf("expected api_key to be [REDACTED], got %v", logged["api_key"])
	}
	if logged["token"] != "[REDACTED]" {
		t.Errorf("expected token to be [REDACTED], got %v", logged["token"])
	}
}

func TestContextLogger_WithAndFromContext(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: &buf,
	}
	base := New(cfg)

	scoped := base.With("tenant", "acme_corp")
	ctx := WithContext(context.Background(), scoped)

	retrieved := FromContext(ctx)
	if retrieved == nil {
		t.Fatalf("expected non-nil logger from context")
	}

	retrieved.Info("tenant event", "action", "invoice_created")

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON, got: %v", err)
	}

	if logged["tenant"] != "acme_corp" {
		t.Errorf("expected tenant 'acme_corp', got %v", logged["tenant"])
	}
	if logged["action"] != "invoice_created" {
		t.Errorf("expected action 'invoice_created', got %v", logged["action"])
	}
}

func TestGlobalLoggingAPI(t *testing.T) {
	var buf bytes.Buffer
	cfg := Config{
		Level:  LevelInfo,
		Format: FormatJSON,
		Output: &buf,
	}
	testLogger := New(cfg)
	SetDefault(testLogger)

	Info("global info event", "service", "payment")

	var logged map[string]any
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("expected valid JSON, got: %v", err)
	}

	if logged["msg"] != "global info event" {
		t.Errorf("expected msg 'global info event', got %v", logged["msg"])
	}
	if logged["service"] != "payment" {
		t.Errorf("expected service 'payment', got %v", logged["service"])
	}
}

func BenchmarkDisabledLogLevel(b *testing.B) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:  LevelError,
		Format: FormatJSON,
		Output: &buf,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		logger.Debug("disabled debug message", "iter", i)
	}
}

func BenchmarkJSONHandler(b *testing.B) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: false,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		logger.Info("benchmarking json logging", "user_id", "u_42", "status", 200)
	}
}

func BenchmarkPrivacyMasking(b *testing.B) {
	var buf bytes.Buffer
	logger := New(Config{
		Level:                LevelInfo,
		Format:               FormatJSON,
		Output:               &buf,
		EnablePrivacyMasking: true,
	})

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buf.Reset()
		logger.Info("benchmarking privacy", "user_id", "u_42", "password", "secret123")
	}
}

