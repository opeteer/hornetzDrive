package log

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"ztatic-go-framework/trace"
)

var reqCounter uint64

// RequestLoggerConfig defines the configuration for the HTTP request logger middleware.
type RequestLoggerConfig struct {
	// Skipper defines a function to skip middleware execution.
	// Defaults to DefaultRequestSkipper.
	Skipper middleware.Skipper

	// Logger is the base *slog.Logger instance. If nil, log.Default() is used.
	Logger *slog.Logger

	// DisableRequestID disables automatic X-Request-ID generation and propagation.
	// Default is false (Request ID is enabled).
	DisableRequestID bool

	// DisableLatency disables recording of request duration.
	// Default is false (Latency is recorded).
	DisableLatency bool

	// DisableRemoteIP disables recording client IP.
	// Default is false (Remote IP is recorded).
	DisableRemoteIP bool

	// DisableUserAgent disables recording client User-Agent.
	// Default is false (User-Agent is recorded).
	DisableUserAgent bool

	// DisableRoute disables recording the matched route pattern.
	// Default is false (Route is recorded).
	DisableRoute bool

	// DisablePayloadSize disables recording bytes received and sent.
	// Default is false (Payload size is recorded).
	DisablePayloadSize bool
}

// DefaultRequestLoggerConfig returns production-ready settings for the request logger.
func DefaultRequestLoggerConfig() RequestLoggerConfig {
	return RequestLoggerConfig{
		Skipper:            DefaultRequestSkipper,
		Logger:             nil,
		DisableRequestID:   false,
		DisableLatency:     false,
		DisableRemoteIP:    false,
		DisableUserAgent:   false,
		DisableRoute:       false,
		DisablePayloadSize: false,
	}
}

// RequestLogger creates an HTTP request logging middleware with default configuration.
func RequestLogger() echo.MiddlewareFunc {
	return RequestLoggerWithConfig(DefaultRequestLoggerConfig())
}

// RequestLoggerWithConfig creates an HTTP request logging middleware with the specified configuration.
func RequestLoggerWithConfig(cfg RequestLoggerConfig) echo.MiddlewareFunc {
	if cfg.Skipper == nil {
		cfg.Skipper = DefaultRequestLoggerConfig().Skipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			start := time.Now()
			req := c.Request()
			res := c.Response()

			// 1. Resolve or generate Request ID and Trace metadata
			tc := trace.FromContext(req.Context())
			reqID := tc.RequestID
			if reqID == "" {
				reqID = req.Header.Get(echo.HeaderXRequestID)
			}
			if reqID == "" && !cfg.DisableRequestID {
				reqID = generateRequestID()
				req.Header.Set(echo.HeaderXRequestID, reqID)
			}
			if reqID != "" {
				res.Header().Set(echo.HeaderXRequestID, reqID)
			}

			// 2. Select base logger
			base := cfg.Logger
			if base == nil {
				base = Default()
			}

			// 3. Create request-scoped child logger with correlation metadata
			loggerAttrs := []any{
				slog.String("req_id", reqID),
				slog.String("method", req.Method),
				slog.String("uri", req.URL.RequestURI()),
			}
			if tc.TraceID != "" {
				loggerAttrs = append(loggerAttrs, slog.String("trace_id", tc.TraceID))
			}
			if tc.SpanID != "" {
				loggerAttrs = append(loggerAttrs, slog.String("span_id", tc.SpanID))
			}
			reqLogger := base.With(loggerAttrs...)
			if !cfg.DisableRemoteIP {
				reqLogger = reqLogger.With(slog.String("ip", c.RealIP()))
			}

			// 4. Bind logger to Echo Context and Request Context
			c.SetLogger(reqLogger)
			ctx := WithContext(req.Context(), reqLogger)
			if reqID != "" {
				ctx = contextWithValue(ctx, ContextKeyRequestID, reqID)
			}
			c.SetRequest(req.WithContext(ctx))

			// 5. Catch runtime panics, log structured error, and safely re-panic
			defer func() {
				if r := recover(); r != nil {
					latency := time.Since(start)
					route := c.Path()
					if route == "" {
						route = req.URL.Path
					}

					reqLogger.Error("HTTP request panic",
						slog.Int("status", http.StatusInternalServerError),
						slog.Duration("latency", latency),
						slog.String("route", route),
						slog.Any("panic", fmt.Sprint(r)),
						slog.String("stack", string(debug.Stack())),
					)
					panic(r)
				}
			}()

			// 6. Execute downstream handler chain
			handlerErr := next(c)

			// 7. Measure latency and resolve response status
			latency := time.Since(start)
			resp, statusCode := echo.ResolveResponseStatus(res, handlerErr)

			// 8. Assemble structured attributes
			route := c.Path()
			if route == "" {
				route = req.URL.Path
			}

			attrs := make([]any, 0, 8)
			attrs = append(attrs,
				slog.Int("status", statusCode),
			)

			if !cfg.DisableLatency {
				attrs = append(attrs, slog.Duration("latency", latency))
			}

			if !cfg.DisableRoute {
				attrs = append(attrs, slog.String("route", route))
			}

			if !cfg.DisablePayloadSize {
				if cl := req.Header.Get(echo.HeaderContentLength); cl != "" {
					attrs = append(attrs, slog.String("bytes_in", cl))
				}
				if resp != nil {
					attrs = append(attrs, slog.Int64("bytes_out", resp.Size))
				}
			}

			if !cfg.DisableUserAgent {
				if ua := req.UserAgent(); ua != "" {
					attrs = append(attrs, slog.String("user_agent", ua))
				}
			}

			// 9. Map status code to appropriate log level
			switch {
			case statusCode >= http.StatusInternalServerError:
				errMsg := ""
				if handlerErr != nil {
					errMsg = handlerErr.Error()
				}
				attrs = append(attrs, slog.String("error", errMsg))
				reqLogger.Error("HTTP request error", attrs...)

			case statusCode >= http.StatusBadRequest:
				if handlerErr != nil {
					attrs = append(attrs, slog.String("error", handlerErr.Error()))
				}
				reqLogger.Warn("HTTP request warning", attrs...)

			default:
				reqLogger.Info("HTTP request", attrs...)
			}

			return handlerErr
		}
	}
}

func contextWithValue(parent context.Context, key, val any) context.Context {
	return context.WithValue(parent, key, val)
}

func generateRequestID() string {
	seq := atomic.AddUint64(&reqCounter, 1)
	randomBytes := make([]byte, 4)
	_, _ = rand.Read(randomBytes)
	return fmt.Sprintf("req-%x-%x-%04x", time.Now().UnixNano(), randomBytes, seq%0xffff)
}
