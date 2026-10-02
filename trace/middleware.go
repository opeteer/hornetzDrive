package trace

import (
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// Middleware returns a tracing and request correlation middleware initialized with default configuration.
func Middleware() echo.MiddlewareFunc {
	return MiddlewareWithConfig(DefaultConfig())
}

// MiddlewareWithConfig returns a tracing and request correlation middleware configured with custom settings.
func MiddlewareWithConfig(cfg Config) echo.MiddlewareFunc {
	if cfg.Skipper == nil {
		cfg.Skipper = middleware.DefaultSkipper
	}
	if cfg.RequestIDHeader == "" {
		cfg.RequestIDHeader = HeaderXRequestID
	}
	if cfg.CorrelationIDHeader == "" {
		cfg.CorrelationIDHeader = HeaderXCorrelationID
	}
	if cfg.TraceparentHeader == "" {
		cfg.TraceparentHeader = HeaderTraceparent
	}
	if cfg.TracestateHeader == "" {
		cfg.TracestateHeader = HeaderTracestate
	}
	if cfg.RequestIDGenerator == nil {
		cfg.RequestIDGenerator = GenerateRequestID
	}
	if cfg.TraceIDGenerator == nil {
		cfg.TraceIDGenerator = GenerateTraceID
	}
	if cfg.SpanIDGenerator == nil {
		cfg.SpanIDGenerator = GenerateSpanID
	}
	if cfg.MaxIDLength <= 0 {
		cfg.MaxIDLength = 128
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			res := c.Response()

			// 1. Resolve or generate Request ID
			var reqID string
			if cfg.TrustIncoming {
				rawID := req.Header.Get(cfg.RequestIDHeader)
				if rawID == "" && cfg.CorrelationIDHeader != "" {
					rawID = req.Header.Get(cfg.CorrelationIDHeader)
				}
				reqID = SanitizeID(rawID, cfg.MaxIDLength)
			}
			if reqID == "" {
				reqID = cfg.RequestIDGenerator()
			}

			// 2. Resolve or generate W3C Trace Context
			var (
				traceID    string
				parentID   string
				sampled    bool
				traceState string
			)

			if cfg.TrustIncoming {
				rawTP := req.Header.Get(cfg.TraceparentHeader)
				if rawTP != "" {
					if tID, pID, s, err := ParseTraceparent(rawTP); err == nil {
						traceID = tID
						parentID = pID
						sampled = s
						traceState = req.Header.Get(cfg.TracestateHeader)
					}
				}
			}

			if traceID == "" {
				traceID = cfg.TraceIDGenerator()
				sampled = cfg.SampleRate >= 1.0 // default sampled
			}

			// Always assign a fresh span ID for the current execution span
			spanID := cfg.SpanIDGenerator()

			// 3. Assemble TraceContext
			tc := TraceContext{
				RequestID:  reqID,
				TraceID:    traceID,
				SpanID:     spanID,
				ParentID:   parentID,
				Sampled:    sampled,
				TraceState: traceState,
			}

			// 4. Update request headers so downstream handlers or proxies can read standard headers
			formattedTP := FormatTraceparent(traceID, spanID, sampled)
			req.Header.Set(cfg.RequestIDHeader, reqID)
			req.Header.Set(cfg.TraceparentHeader, formattedTP)
			if traceState != "" {
				req.Header.Set(cfg.TracestateHeader, traceState)
			}

			// 5. Inject outbound headers into HTTP response
			if cfg.EnableResponseHeaders {
				res.Header().Set(cfg.RequestIDHeader, reqID)
				res.Header().Set(cfg.TraceparentHeader, formattedTP)
				if traceState != "" {
					res.Header().Set(cfg.TracestateHeader, traceState)
				}
			}

			// 6. Bind to standard context.Context and sync with echo.Context
			ctx := WithContext(req.Context(), tc)
			c.SetRequest(req.WithContext(ctx))

			// 7. Bind directly to echo.Context for fast retrieval
			c.Set("trace_context", tc)
			c.Set("request_id", reqID)
			c.Set("trace_id", traceID)
			c.Set("span_id", spanID)

			return next(c)
		}
	}
}
