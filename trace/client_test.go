package trace

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestInject_And_Transport(t *testing.T) {
	// Dummy upstream server that inspects incoming headers
	var capturedReqID, capturedTP, capturedTS string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReqID = r.Header.Get(HeaderXRequestID)
		capturedTP = r.Header.Get(HeaderTraceparent)
		capturedTS = r.Header.Get(HeaderTracestate)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Prepare parent trace context
	tc := TraceContext{
		RequestID:  "req-client-orig-123",
		TraceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		SpanID:     "00f067aa0ba902b7",
		Sampled:    true,
		TraceState: "state=test",
	}
	ctx := WithContext(context.Background(), tc)

	client := NewClient(server.Client())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("failed to execute request: %v", err)
	}
	defer resp.Body.Close()

	if capturedReqID != "req-client-orig-123" {
		t.Errorf("expected outbound request to carry RequestID req-client-orig-123, got %s", capturedReqID)
	}
	if capturedTS != "state=test" {
		t.Errorf("expected outbound request to carry TraceState state=test, got %s", capturedTS)
	}

	// Verify traceparent
	traceID, outboundSpan, sampled, err := ParseTraceparent(capturedTP)
	if err != nil {
		t.Fatalf("outbound traceparent is invalid: %v", err)
	}
	if traceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected traceID to be propagated, got %s", traceID)
	}
	if outboundSpan == "" || len(outboundSpan) != 16 {
		t.Errorf("expected valid 16-hex outbound span ID, got %s", outboundSpan)
	}
	if !sampled {
		t.Errorf("expected sampled true, got false")
	}
}
