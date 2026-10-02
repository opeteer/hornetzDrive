package trace

import (
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// Header constants for distributed tracing and request correlation
const (
	HeaderXRequestID     = echo.HeaderXRequestID
	HeaderXCorrelationID = "X-Correlation-ID"
	HeaderTraceparent    = "traceparent"
	HeaderTracestate     = "tracestate"
)

// Config defines the configuration for the tracing and request correlation middleware.
type Config struct {
	// Skipper defines a function to skip middleware execution for certain requests.
	Skipper middleware.Skipper

	// RequestIDHeader is the HTTP header name for request correlation.
	// Defaults to "X-Request-Id".
	RequestIDHeader string

	// CorrelationIDHeader is an optional alternative header to check for incoming correlation IDs.
	// Defaults to "X-Correlation-ID".
	CorrelationIDHeader string

	// TraceparentHeader is the W3C Trace Context traceparent header name.
	// Defaults to "traceparent".
	TraceparentHeader string

	// TracestateHeader is the W3C Trace Context tracestate header name.
	// Defaults to "tracestate".
	TracestateHeader string

	// TrustIncoming indicates whether incoming request IDs and trace contexts are accepted.
	// When true (default), incoming IDs are sanitized; when false, new IDs are always generated.
	TrustIncoming bool

	// EnableResponseHeaders sets X-Request-ID and traceparent on outgoing HTTP responses.
	// Defaults to true.
	EnableResponseHeaders bool

	// MaxIDLength specifies the maximum allowed byte length for incoming request IDs.
	// Defaults to 128.
	MaxIDLength int

	// SampleRate specifies the default sampling probability (0.0 to 1.0) when no incoming traceparent exists.
	// Defaults to 1.0 (always sampled).
	SampleRate float64

	// RequestIDGenerator defines a custom function to generate request IDs.
	// If nil, GenerateRequestID is used.
	RequestIDGenerator func() string

	// TraceIDGenerator defines a custom function to generate 16-byte trace IDs.
	// If nil, GenerateTraceID is used.
	TraceIDGenerator func() string

	// SpanIDGenerator defines a custom function to generate 8-byte span IDs.
	// If nil, GenerateSpanID is used.
	SpanIDGenerator func() string
}

// DefaultConfig returns production-ready tracing configuration.
func DefaultConfig() Config {
	return Config{
		Skipper:               middleware.DefaultSkipper,
		RequestIDHeader:       HeaderXRequestID,
		CorrelationIDHeader:   HeaderXCorrelationID,
		TraceparentHeader:     HeaderTraceparent,
		TracestateHeader:      HeaderTracestate,
		TrustIncoming:         true,
		EnableResponseHeaders: true,
		MaxIDLength:           128,
		SampleRate:            1.0,
		RequestIDGenerator:    GenerateRequestID,
		TraceIDGenerator:      GenerateTraceID,
		SpanIDGenerator:       GenerateSpanID,
	}
}
