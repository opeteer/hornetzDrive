package log

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"

	"ztatic-go-framework/security/privacy"
	"ztatic-go-framework/trace"
)

// Standard context keys for request and tracing correlation
type contextKey string

const (
	// ContextKeyRequestID is the context key for Request ID correlation.
	ContextKeyRequestID contextKey = "ztatic_request_id"
	// ContextKeyTraceID is the context key for distributed trace ID.
	ContextKeyTraceID contextKey = "ztatic_trace_id"
	// ContextKeySpanID is the context key for distributed span ID.
	ContextKeySpanID contextKey = "ztatic_span_id"
	// ContextKeyUserID is the context key for authenticated user ID.
	ContextKeyUserID contextKey = "ztatic_user_id"
	// ContextKeyTenantID is the context key for multi-tenant isolation.
	ContextKeyTenantID contextKey = "ztatic_tenant_id"
)

// ContextHandler is an slog.Handler middleware that automatically inspects
// context.Context for correlation IDs (request_id, trace_id, user_id) and attaches
// them as structured attributes to outgoing log records.
type ContextHandler struct {
	inner slog.Handler
}

// NewContextHandler wraps an existing slog.Handler with context correlation extraction.
func NewContextHandler(inner slog.Handler) *ContextHandler {
	return &ContextHandler{inner: inner}
}

// Enabled passes through to the inner handler.
func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle inspects context.Context for correlation metadata, attaches found attributes,
// and delegates to the inner handler.
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx == nil {
		return h.inner.Handle(ctx, r)
	}

	var extraAttrs []slog.Attr

	// Extract from unified trace.TraceContext if present
	tc := trace.FromContext(ctx)

	// Extract standard typed context keys
	if tc.RequestID != "" {
		extraAttrs = append(extraAttrs, slog.String("req_id", tc.RequestID))
	} else if reqID := ctx.Value(ContextKeyRequestID); reqID != nil {
		extraAttrs = append(extraAttrs, slog.String("req_id", fmt.Sprint(reqID)))
	} else if reqID := ctx.Value("request_id"); reqID != nil {
		extraAttrs = append(extraAttrs, slog.String("req_id", fmt.Sprint(reqID)))
	} else if reqID := ctx.Value("req_id"); reqID != nil {
		extraAttrs = append(extraAttrs, slog.String("req_id", fmt.Sprint(reqID)))
	}

	if tc.TraceID != "" {
		extraAttrs = append(extraAttrs, slog.String("trace_id", tc.TraceID))
	} else if traceID := ctx.Value(ContextKeyTraceID); traceID != nil {
		extraAttrs = append(extraAttrs, slog.String("trace_id", fmt.Sprint(traceID)))
	} else if traceID := ctx.Value("trace_id"); traceID != nil {
		extraAttrs = append(extraAttrs, slog.String("trace_id", fmt.Sprint(traceID)))
	}

	if tc.SpanID != "" {
		extraAttrs = append(extraAttrs, slog.String("span_id", tc.SpanID))
	} else if spanID := ctx.Value(ContextKeySpanID); spanID != nil {
		extraAttrs = append(extraAttrs, slog.String("span_id", fmt.Sprint(spanID)))
	} else if spanID := ctx.Value("span_id"); spanID != nil {
		extraAttrs = append(extraAttrs, slog.String("span_id", fmt.Sprint(spanID)))
	}

	if userID := ctx.Value(ContextKeyUserID); userID != nil {
		extraAttrs = append(extraAttrs, slog.String("user_id", fmt.Sprint(userID)))
	} else if userID := ctx.Value("user_id"); userID != nil {
		extraAttrs = append(extraAttrs, slog.String("user_id", fmt.Sprint(userID)))
	}

	if tenantID := ctx.Value(ContextKeyTenantID); tenantID != nil {
		extraAttrs = append(extraAttrs, slog.String("tenant_id", fmt.Sprint(tenantID)))
	} else if tenantID := ctx.Value("tenant_id"); tenantID != nil {
		extraAttrs = append(extraAttrs, slog.String("tenant_id", fmt.Sprint(tenantID)))
	}

	if len(extraAttrs) > 0 {
		// Clone record with additional context attributes
		cloned := slog.NewRecord(r.Time, r.Level, r.Message, r.PC)
		cloned.AddAttrs(extraAttrs...)
		r.Attrs(func(a slog.Attr) bool {
			cloned.AddAttrs(a)
			return true
		})
		return h.inner.Handle(ctx, cloned)
	}

	return h.inner.Handle(ctx, r)
}

// WithAttrs passes through to the inner handler.
func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{inner: h.inner.WithAttrs(attrs)}
}

// WithGroup passes through to the inner handler.
func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{inner: h.inner.WithGroup(name)}
}

// NewHandler builds a full structured logging handler pipeline from Config:
// [ContextHandler] -> [LogMasker (privacy)] -> [Base Formatter (JSON/Console/Text)].
func NewHandler(cfg Config) slog.Handler {
	var out io.Writer = os.Stdout
	if cfg.Output != nil {
		out = cfg.Output
	}

	var leveler slog.Leveler = slog.LevelInfo
	if cfg.LevelVar != nil {
		leveler = cfg.LevelVar
	} else {
		leveler = cfg.Level
	}

	var base slog.Handler
	switch cfg.Format {
	case FormatConsole:
		base = NewConsoleHandler(out, &ConsoleHandlerOptions{
			Level:     leveler,
			AddSource: cfg.AddSource,
		})
	case FormatText:
		base = slog.NewTextHandler(out, &slog.HandlerOptions{
			Level:     leveler,
			AddSource: cfg.AddSource,
		})
	case FormatJSON:
		fallthrough
	default:
		base = slog.NewJSONHandler(out, &slog.HandlerOptions{
			Level:     leveler,
			AddSource: cfg.AddSource,
		})
	}

	// Layer 2: Automatic PII & sensitive credentials scrubbing
	var masked slog.Handler = base
	if cfg.EnablePrivacyMasking {
		masked = privacy.NewLogMasker(base)
	}

	// Layer 1: Context correlation ID extraction (request_id, trace_id, user_id)
	return NewContextHandler(masked)
}
