package trace

import (
	"context"
	"testing"
)

func TestTraceContext_Propagation(t *testing.T) {
	tc := TraceContext{
		RequestID:  "req-custom-99",
		TraceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:     "00f067aa0ba902b7",
		ParentID:   "5a4f3b2c1d0e9f8a",
		Sampled:    true,
		TraceState: "congo=t61rcWkgMzE",
	}

	ctx := WithContext(context.Background(), tc)

	retrieved := FromContext(ctx)
	if retrieved.RequestID != tc.RequestID {
		t.Errorf("expected RequestID %s, got %s", tc.RequestID, retrieved.RequestID)
	}
	if retrieved.TraceID != tc.TraceID {
		t.Errorf("expected TraceID %s, got %s", tc.TraceID, retrieved.TraceID)
	}
	if retrieved.SpanID != tc.SpanID {
		t.Errorf("expected SpanID %s, got %s", tc.SpanID, retrieved.SpanID)
	}
	if retrieved.ParentID != tc.ParentID {
		t.Errorf("expected ParentID %s, got %s", tc.ParentID, retrieved.ParentID)
	}
	if retrieved.Sampled != tc.Sampled {
		t.Errorf("expected Sampled %v, got %v", tc.Sampled, retrieved.Sampled)
	}
	if retrieved.TraceState != tc.TraceState {
		t.Errorf("expected TraceState %s, got %s", tc.TraceState, retrieved.TraceState)
	}

	// Verify individual helper functions
	if RequestID(ctx) != tc.RequestID {
		t.Errorf("expected RequestID(ctx) %s, got %s", tc.RequestID, RequestID(ctx))
	}
	if TraceID(ctx) != tc.TraceID {
		t.Errorf("expected TraceID(ctx) %s, got %s", tc.TraceID, TraceID(ctx))
	}
	if SpanID(ctx) != tc.SpanID {
		t.Errorf("expected SpanID(ctx) %s, got %s", tc.SpanID, SpanID(ctx))
	}
}

func TestTraceContext_FallbackReconstruction(t *testing.T) {
	// Context with legacy/fallback keys
	ctx := context.WithValue(context.Background(), "request_id", "req-legacy-1")
	ctx = context.WithValue(ctx, "trace_id", "trace-legacy-2")
	ctx = context.WithValue(ctx, "span_id", "span-legacy-3")

	tc := FromContext(ctx)
	if tc.RequestID != "req-legacy-1" {
		t.Errorf("expected RequestID req-legacy-1, got %s", tc.RequestID)
	}
	if tc.TraceID != "trace-legacy-2" {
		t.Errorf("expected TraceID trace-legacy-2, got %s", tc.TraceID)
	}
	if tc.SpanID != "span-legacy-3" {
		t.Errorf("expected SpanID span-legacy-3, got %s", tc.SpanID)
	}
}

func TestWithRequestID_WithTraceID(t *testing.T) {
	ctx := WithRequestID(context.Background(), "req-explicit-1")
	if RequestID(ctx) != "req-explicit-1" {
		t.Errorf("expected req-explicit-1, got %s", RequestID(ctx))
	}

	ctx = WithTraceID(ctx, "trace-explicit-2")
	if TraceID(ctx) != "trace-explicit-2" {
		t.Errorf("expected trace-explicit-2, got %s", TraceID(ctx))
	}
	// RequestID should still be preserved
	if RequestID(ctx) != "req-explicit-1" {
		t.Errorf("expected req-explicit-1 to be preserved, got %s", RequestID(ctx))
	}
}
