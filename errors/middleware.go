package errors

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/trace"
)

// NewHTTPErrorHandler creates an Echo v5 compatible HTTPErrorHandler that standardizes all errors.
func NewHTTPErrorHandler(cfg Config) echo.HTTPErrorHandler {
	mapper := cfg.Mapper
	if mapper == nil {
		mapper = DefaultMapper
	}

	return func(c *echo.Context, err error) {
		if err == nil {
			return
		}

		// 1. Guard against double-writing if the response is already committed.
		if r, _ := echo.UnwrapResponse(c.Response()); r != nil && r.Committed {
			c.Logger().Warn("error occurred after response was committed",
				slog.String("error", err.Error()),
				slog.String("route", c.Path()),
			)
			return
		}

		// 2. Resolve Request ID & Trace ID
		tc := trace.FromContext(c.Request().Context())
		reqID := tc.RequestID
		if reqID == "" {
			reqID = c.Response().Header().Get(echo.HeaderXRequestID)
			if reqID == "" {
				reqID = c.Request().Header.Get(echo.HeaderXRequestID)
			}
		}

		traceID := tc.TraceID
		if traceID == "" {
			if val, ok := c.Get("trace_id").(string); ok && val != "" {
				traceID = val
			}
		}

		// 3. Map error to standardized *Error
		appErr := mapper.Map(err)
		if appErr.RequestID == "" {
			appErr.RequestID = reqID
		}
		if appErr.TraceID == "" {
			appErr.TraceID = traceID
		}

		// 4. Invoke external APM / Sentry hook if configured
		if cfg.OnError != nil {
			cfg.OnError(c, err, appErr)
		}

		// 5. Correlate with structured logger (slog)
		status := appErr.StatusCode()
		logger := c.Logger()
		if logger != nil {
			logAttrs := []any{
				slog.Int("status", status),
				slog.String("code", appErr.Code),
				slog.String("req_id", reqID),
				slog.String("route", c.Path()),
				slog.String("method", c.Request().Method),
				slog.String("uri", c.Request().URL.RequestURI()),
			}
			if traceID != "" {
				logAttrs = append(logAttrs, slog.String("trace_id", traceID))
			}
			if appErr.Internal != nil {
				logAttrs = append(logAttrs, slog.String("cause", appErr.Internal.Error()))
			}

			switch {
			case status >= http.StatusInternalServerError:
				if appErr.Stack != "" {
					logAttrs = append(logAttrs, slog.String("stack", appErr.Stack))
				}
				logger.Error("request failed with internal error", logAttrs...)
			case status >= http.StatusBadRequest:
				logger.Warn("request failed with client error", logAttrs...)
			default:
				logger.Info("request completed with mapped status", logAttrs...)
			}
		}

		// 6. Handle HEAD requests (do not write body)
		if c.Request().Method == http.MethodHead {
			_ = c.NoContent(status)
			return
		}

		// 7. Render standardized error response
		if renderErr := Render(c, appErr, cfg); renderErr != nil {
			c.Logger().Error("failed to render standardized error response",
				slog.String("render_error", renderErr.Error()),
				slog.String("req_id", reqID),
				slog.String("trace_id", traceID),
			)
		}
	}
}

// RecoverMiddleware returns a panic-recovery middleware using default error configuration.
func RecoverMiddleware() echo.MiddlewareFunc {
	return RecoverMiddlewareWithConfig(DefaultConfig())
}

// RecoverMiddlewareWithConfig returns an Echo middleware that safely catches panics,
// logs the stack trace, and delegates to the standardized HTTP error handler.
func RecoverMiddlewareWithConfig(cfg Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) (err error) {
			defer func() {
				if r := recover(); r != nil {
					var panicErr error
					if pErr, ok := r.(error); ok {
						panicErr = pErr
					} else {
						panicErr = fmt.Errorf("panic: %v", r)
					}

					stack := string(debug.Stack())
					appErr := Internal("A critical server panic occurred").
						WithInternal(panicErr)
					appErr.Stack = stack
					err = appErr
				}
			}()

			return next(c)
		}
	}
}
