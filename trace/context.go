package trace

import (
	"context"
)

// TraceContext represents the distributed tracing and request correlation state.
type TraceContext struct {
	// RequestID is the unique human-readable or correlation identifier for the request.
	RequestID string `json:"request_id"`

	// TraceID is the 16-byte (32 hex character) distributed trace identifier.
	TraceID string `json:"trace_id"`

	// SpanID is the 8-byte (16 hex character) identifier of the current execution span.
	SpanID string `json:"span_id"`

	// ParentID is the 8-byte (16 hex character) identifier of the parent/caller span, if any.
	ParentID string `json:"parent_id,omitempty"`

	// Sampled indicates whether this trace was selected for recording/sampling.
	Sampled bool `json:"sampled"`

	// TraceState contains vendor-specific state information passed in W3C tracestate.
	TraceState string `json:"trace_state,omitempty"`
}

// IsZero reports whether the trace context is uninitialized.
func (tc TraceContext) IsZero() bool {
	return tc.RequestID == "" && tc.TraceID == "" && tc.SpanID == ""
}

// Context keys to avoid collisions
type (
	contextKeyTraceContext struct{}
	contextKeyRequestID    struct{}
	contextKeyTraceID      struct{}
	contextKeySpanID       struct{}
)

// String key fallbacks matching framework conventions
const (
	FallbackKeyRequestID = "ztatic_request_id"
	FallbackKeyTraceID   = "ztatic_trace_id"
	FallbackKeySpanID    = "ztatic_span_id"
)

// WithContext returns a child context storing the provided TraceContext.
func WithContext(parent context.Context, tc TraceContext) context.Context {
	if parent == nil {
		parent = context.Background()
	}
	ctx := context.WithValue(parent, contextKeyTraceContext{}, tc)
	if tc.RequestID != "" {
		ctx = context.WithValue(ctx, contextKeyRequestID{}, tc.RequestID)
		ctx = context.WithValue(ctx, FallbackKeyRequestID, tc.RequestID)
	}
	if tc.TraceID != "" {
		ctx = context.WithValue(ctx, contextKeyTraceID{}, tc.TraceID)
		ctx = context.WithValue(ctx, FallbackKeyTraceID, tc.TraceID)
	}
	if tc.SpanID != "" {
		ctx = context.WithValue(ctx, contextKeySpanID{}, tc.SpanID)
		ctx = context.WithValue(ctx, FallbackKeySpanID, tc.SpanID)
	}
	return ctx
}

// FromContext extracts the TraceContext from the given context.Context.
// If not found as a full TraceContext, it attempts to reconstruct one from individual keys.
func FromContext(ctx context.Context) TraceContext {
	if ctx == nil {
		return TraceContext{}
	}

	if tc, ok := ctx.Value(contextKeyTraceContext{}).(TraceContext); ok {
		return tc
	}

	// Fallback reconstruction
	var tc TraceContext
	if reqID := RequestID(ctx); reqID != "" {
		tc.RequestID = reqID
	}
	if traceID := TraceID(ctx); traceID != "" {
		tc.TraceID = traceID
	}
	if spanID := SpanID(ctx); spanID != "" {
		tc.SpanID = spanID
	}
	return tc
}

// RequestID extracts the request correlation ID from the context.
func RequestID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(contextKeyRequestID{}).(string); ok && v != "" {
		return v
	}
	if tc, ok := ctx.Value(contextKeyTraceContext{}).(TraceContext); ok && tc.RequestID != "" {
		return tc.RequestID
	}
	if v, ok := ctx.Value(FallbackKeyRequestID).(string); ok && v != "" {
		return v
	}
	if v, ok := ctx.Value("request_id").(string); ok && v != "" {
		return v
	}
	if v, ok := ctx.Value("req_id").(string); ok && v != "" {
		return v
	}
	return ""
}

// TraceID extracts the distributed trace ID from the context.
func TraceID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(contextKeyTraceID{}).(string); ok && v != "" {
		return v
	}
	if tc, ok := ctx.Value(contextKeyTraceContext{}).(TraceContext); ok && tc.TraceID != "" {
		return tc.TraceID
	}
	if v, ok := ctx.Value(FallbackKeyTraceID).(string); ok && v != "" {
		return v
	}
	if v, ok := ctx.Value("trace_id").(string); ok && v != "" {
		return v
	}
	return ""
}

// SpanID extracts the span ID from the context.
func SpanID(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v, ok := ctx.Value(contextKeySpanID{}).(string); ok && v != "" {
		return v
	}
	if tc, ok := ctx.Value(contextKeyTraceContext{}).(TraceContext); ok && tc.SpanID != "" {
		return tc.SpanID
	}
	if v, ok := ctx.Value(FallbackKeySpanID).(string); ok && v != "" {
		return v
	}
	if v, ok := ctx.Value("span_id").(string); ok && v != "" {
		return v
	}
	return ""
}

// WithRequestID binds an explicit request ID into context.
func WithRequestID(parent context.Context, reqID string) context.Context {
	tc := FromContext(parent)
	tc.RequestID = reqID
	return WithContext(parent, tc)
}

// WithTraceID binds an explicit distributed trace ID into context.
func WithTraceID(parent context.Context, traceID string) context.Context {
	tc := FromContext(parent)
	tc.TraceID = traceID
	return WithContext(parent, tc)
}
