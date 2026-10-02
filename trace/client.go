package trace

import (
	"context"
	"net/http"
)

// Inject populates tracing headers (X-Request-ID, traceparent, tracestate) onto an outgoing HTTP request.
// If tc.TraceID is present, a fresh child span ID is generated for the outbound request.
func Inject(ctx context.Context, req *http.Request) {
	if ctx == nil || req == nil {
		return
	}

	tc := FromContext(ctx)
	if tc.IsZero() {
		return
	}

	if tc.RequestID != "" {
		req.Header.Set(HeaderXRequestID, tc.RequestID)
	}

	if tc.TraceID != "" {
		// Create a new span ID for the outbound call with tc.SpanID as the parent
		outboundSpanID := GenerateSpanID()
		req.Header.Set(HeaderTraceparent, FormatTraceparent(tc.TraceID, outboundSpanID, tc.Sampled))
	}

	if tc.TraceState != "" {
		req.Header.Set(HeaderTracestate, tc.TraceState)
	}
}

// Transport wraps an http.RoundTripper to automatically propagate tracing context
// on outgoing HTTP client calls to other services.
type Transport struct {
	Base http.RoundTripper
}

// NewTransport creates an http.RoundTripper that automatically propagates tracing headers.
func NewTransport(base http.RoundTripper) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &Transport{Base: base}
}

// RoundTrip executes a single HTTP transaction while injecting tracing headers from req.Context().
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Clone request so headers can be safely modified without mutating caller's request
	reqCopy := req.Clone(req.Context())
	Inject(reqCopy.Context(), reqCopy)
	return t.Base.RoundTrip(reqCopy)
}

// NewClient returns a copy of the provided http.Client with its Transport wrapped in a tracing Transport.
// If client is nil, http.DefaultClient is used as base.
func NewClient(client *http.Client) *http.Client {
	var c http.Client
	if client != nil {
		c = *client
	}
	c.Transport = NewTransport(c.Transport)
	return &c
}
