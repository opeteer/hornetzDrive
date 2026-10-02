package privacy

import (
	"context"
	"log/slog"
	"strings"
)

const RedactedString = "[REDACTED]"

var defaultSensitiveKeys = []string{
	"password", "pass", "secret", "token", "auth", "authorization",
	"api_key", "apikey", "ssn", "credit_card", "card_number", "cvv",
}

// LogMasker wraps an slog.Handler to automatically redact sensitive information.
type LogMasker struct {
	handler slog.Handler
}

// NewLogMasker creates a new PII & secret scrubbing log handler.
func NewLogMasker(h slog.Handler) *LogMasker {
	return &LogMasker{handler: h}
}

// Enabled passes through to the underlying handler.
func (m *LogMasker) Enabled(ctx context.Context, level slog.Level) bool {
	return m.handler.Enabled(ctx, level)
}

// Handle intercepts the log record, masks sensitive attributes, and passes it down.
func (m *LogMasker) Handle(ctx context.Context, r slog.Record) error {
	newRecord := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
	
	r.Attrs(func(a slog.Attr) bool {
		newRecord.AddAttrs(m.maskAttr(a))
		return true
	})

	return m.handler.Handle(ctx, newRecord)
}

// WithAttrs passes masked attributes to the underlying handler.
func (m *LogMasker) WithAttrs(attrs []slog.Attr) slog.Handler {
	masked := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		masked[i] = m.maskAttr(a)
	}
	return &LogMasker{handler: m.handler.WithAttrs(masked)}
}

// WithGroup passes the group to the underlying handler.
func (m *LogMasker) WithGroup(name string) slog.Handler {
	return &LogMasker{handler: m.handler.WithGroup(name)}
}

func (m *LogMasker) maskAttr(a slog.Attr) slog.Attr {
	if isSensitiveKey(a.Key) {
		return slog.String(a.Key, RedactedString)
	}
	
	// Handle nested groups
	if a.Value.Kind() == slog.KindGroup {
		attrs := a.Value.Group()
		masked := make([]any, len(attrs))
		for i, attr := range attrs {
			masked[i] = m.maskAttr(attr)
		}
		return slog.Group(a.Key, masked...)
	}

	return a
}

func isSensitiveKey(key string) bool {
	return IsSensitiveKey(key)
}

// IsSensitiveKey returns true if the key matches known sensitive patterns (passwords, tokens, keys, card numbers, etc.).
func IsSensitiveKey(key string) bool {
	lowerKey := strings.ToLower(key)
	for _, sensitive := range defaultSensitiveKeys {
		if strings.Contains(lowerKey, sensitive) {
			return true
		}
	}
	return false
}

// SanitizeMap creates a deep copy of the map with sensitive fields redacted with RedactedString.
func SanitizeMap(data map[string]any) map[string]any {
	if data == nil {
		return nil
	}
	result := make(map[string]any, len(data))
	for k, v := range data {
		if IsSensitiveKey(k) {
			result[k] = RedactedString
			continue
		}
		switch val := v.(type) {
		case map[string]any:
			result[k] = SanitizeMap(val)
		case []any:
			result[k] = sanitizeSlice(val)
		default:
			result[k] = v
		}
	}
	return result
}

func sanitizeSlice(slice []any) []any {
	result := make([]any, len(slice))
	for i, item := range slice {
		switch v := item.(type) {
		case map[string]any:
			result[i] = SanitizeMap(v)
		case []any:
			result[i] = sanitizeSlice(v)
		default:
			result[i] = v
		}
	}
	return result
}
