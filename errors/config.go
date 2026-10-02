package errors

import (
	"net/http"
	"os"

	"github.com/labstack/echo/v5"
)

// Response format identifiers.
const (
	// FormatEnvelope outputs standard REST API error envelopes: {"error": {...}}
	FormatEnvelope = "envelope"
	// FormatProblemDetails outputs RFC 9457 / RFC 7807 problem details: application/problem+json
	FormatProblemDetails = "problem_details"
)

// Config defines the configuration for the Error Standardization engine.
type Config struct {
	// Format defines the wire representation (FormatEnvelope or FormatProblemDetails).
	// Default is FormatEnvelope.
	Format string

	// ExposeInternalErrors controls whether internal root cause errors and stack traces
	// are serialized into the HTTP response.
	// Default is false (safe for production; automatically enabled if APP_ENV=development).
	ExposeInternalErrors bool

	// EnableStackTrace captures and includes stack traces in development mode.
	EnableStackTrace bool

	// FallbackMessage is the client-safe message used for 5xx Internal Server Errors in production.
	// Defaults to "An unexpected error occurred. Please contact support with the request ID."
	FallbackMessage string

	// ValidationStatus is the HTTP status code emitted for struct validation errors.
	// Default is 422 (StatusUnprocessableEntity).
	ValidationStatus int

	// Mapper is the custom error mapper. If nil, DefaultMapper is used.
	Mapper *Mapper

	// OnError is an optional observability hook invoked whenever an error is processed.
	// Useful for dispatching notifications to APM systems (Sentry, OpenTelemetry, Datadog).
	OnError func(c *echo.Context, rawErr error, appErr *Error)

	// HTMLRenderer optionally allows providing a custom HTML error page renderer.
	HTMLRenderer func(c *echo.Context, appErr *Error) error
}

// DefaultConfig returns safe-by-default enterprise error configuration.
func DefaultConfig() Config {
	isDev := os.Getenv("APP_ENV") == "development"
	return Config{
		Format:               FormatEnvelope,
		ExposeInternalErrors: isDev,
		EnableStackTrace:     isDev,
		FallbackMessage:      "An unexpected error occurred. Please contact support with the request ID.",
		ValidationStatus:     http.StatusUnprocessableEntity,
		Mapper:               nil,
		OnError:              nil,
		HTMLRenderer:         nil,
	}
}
