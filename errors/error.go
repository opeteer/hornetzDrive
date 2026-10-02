package errors

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
)

// Re-export standard library error functions for seamless developer ergonomics.
var (
	// Is reports whether any error in err's tree matches target.
	Is = errors.Is
	// As finds the first error in err's tree that matches target.
	As = errors.As
	// Unwrap returns the result of calling the Unwrap method on err.
	Unwrap = errors.Unwrap
	// Join returns an error that wraps the given errors.
	Join = errors.Join
)

// Standard machine-readable Error Codes.
const (
	CodeBadRequest         = "BAD_REQUEST"
	CodeUnauthorized       = "UNAUTHORIZED"
	CodeForbidden          = "FORBIDDEN"
	CodeNotFound           = "NOT_FOUND"
	CodeConflict           = "CONFLICT"
	CodeValidation         = "VALIDATION_FAILED"
	CodePayloadTooLarge    = "PAYLOAD_TOO_LARGE"
	CodeUnsupportedMedia   = "UNSUPPORTED_MEDIA_TYPE"
	CodeRateLimited        = "RATE_LIMITED"
	CodeClientClosed       = "CLIENT_CLOSED_REQUEST"
	CodeInternal           = "INTERNAL_ERROR"
	CodeNotImplemented     = "NOT_IMPLEMENTED"
	CodeBadGateway         = "BAD_GATEWAY"
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE"
	CodeGatewayTimeout     = "GATEWAY_TIMEOUT"
)

// FieldViolation represents a single validation failure on a struct field or input parameter.
type FieldViolation struct {
	Field   string `json:"field"`
	Rule    string `json:"rule"`
	Message string `json:"message"`
	Value   any    `json:"value,omitempty"`
}

// Error represents a standardized, rich domain application error in Ztatic.
// It decouples business logic from HTTP transport concerns while carrying
// all metadata necessary for high-fidelity API serialization, logging, and security sanitization.
type Error struct {
	Code      string           `json:"code"`
	Message   string           `json:"message"`
	Status    int              `json:"status"`
	Internal  error            `json:"-"`
	Details   []FieldViolation `json:"details,omitempty"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
	RequestID string           `json:"request_id,omitempty"`
	TraceID   string           `json:"trace_id,omitempty"`
	Stack     string           `json:"stack,omitempty"`
}

// Error implements the standard Go error interface.
func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.Internal != nil {
		return fmt.Sprintf("[%s] %s: %v", e.Code, e.Message, e.Internal)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// Unwrap supports standard Go 1.13+ error unwrapping via errors.Is and errors.As.
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Internal
}

// StatusCode implements Echo's HTTPStatusCoder interface.
func (e *Error) StatusCode() int {
	if e == nil {
		return 0
	}
	if e.Status != 0 {
		return e.Status
	}
	return http.StatusInternalServerError
}

// Format implements fmt.Formatter for custom printing (e.g. %+v for stack trace).
func (e *Error) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			_, _ = io.WriteString(s, e.Error())
			if e.Stack != "" {
				_, _ = fmt.Fprintf(s, "\nStack Trace:\n%s", e.Stack)
			}
			return
		}
		fallthrough
	case 's':
		_, _ = io.WriteString(s, e.Error())
	case 'q':
		_, _ = fmt.Fprintf(s, "%q", e.Error())
	}
}

// MarshalJSON customizes JSON serialization of the Error.
func (e *Error) MarshalJSON() ([]byte, error) {
	type Alias Error
	return json.Marshal(&struct {
		*Alias
		InternalErr string `json:"internal,omitempty"`
	}{
		Alias: (*Alias)(e),
		InternalErr: func() string {
			if e.Internal != nil {
				return e.Internal.Error()
			}
			return ""
		}(),
	})
}

// Clone creates a shallow clone of the Error with deep-copied metadata and details.
func (e *Error) Clone() *Error {
	if e == nil {
		return nil
	}
	clone := *e
	if e.Details != nil {
		clone.Details = make([]FieldViolation, len(e.Details))
		copy(clone.Details, e.Details)
	}
	if e.Metadata != nil {
		clone.Metadata = make(map[string]any, len(e.Metadata))
		for k, v := range e.Metadata {
			clone.Metadata[k] = v
		}
	}
	return &clone
}

// --- Fluent Builder Modifiers ---

// WithInternal sets the underlying root cause error.
func (e *Error) WithInternal(err error) *Error {
	clone := e.Clone()
	clone.Internal = err
	return clone
}

// WithStatus overrides the HTTP status code.
func (e *Error) WithStatus(status int) *Error {
	clone := e.Clone()
	clone.Status = status
	return clone
}

// WithDetails attaches field-level validation violations.
func (e *Error) WithDetails(violations ...FieldViolation) *Error {
	clone := e.Clone()
	clone.Details = append(clone.Details, violations...)
	return clone
}

// WithMetadata attaches an arbitrary key-value context pair.
func (e *Error) WithMetadata(key string, value any) *Error {
	clone := e.Clone()
	if clone.Metadata == nil {
		clone.Metadata = make(map[string]any)
	}
	clone.Metadata[key] = value
	return clone
}

// WithRequestID sets the request/correlation ID on the error.
func (e *Error) WithRequestID(reqID string) *Error {
	clone := e.Clone()
	clone.RequestID = reqID
	return clone
}

// WithTraceID sets the distributed trace ID on the error.
func (e *Error) WithTraceID(traceID string) *Error {
	clone := e.Clone()
	clone.TraceID = traceID
	return clone
}

// WithStack captures the current goroutine stack trace onto the error.
func (e *Error) WithStack() *Error {
	clone := e.Clone()
	clone.Stack = string(debug.Stack())
	return clone
}

// --- Error Constructors ---

// New instantiates a new Error with a code and safe user-facing message.
func New(code, message string) *Error {
	return &Error{
		Code:    code,
		Message: message,
	}
}

// Wrap wraps an existing error with a code and client message.
func Wrap(err error, code, message string) *Error {
	if err == nil {
		return nil
	}
	return &Error{
		Code:     code,
		Message:  message,
		Internal: err,
	}
}

// BadRequest creates an HTTP 400 Bad Request error.
func BadRequest(message string) *Error {
	return &Error{
		Code:    CodeBadRequest,
		Message: message,
		Status:  http.StatusBadRequest,
	}
}

// Unauthorized creates an HTTP 401 Unauthorized error.
func Unauthorized(message string) *Error {
	return &Error{
		Code:    CodeUnauthorized,
		Message: message,
		Status:  http.StatusUnauthorized,
	}
}

// Forbidden creates an HTTP 403 Forbidden error.
func Forbidden(message string) *Error {
	return &Error{
		Code:    CodeForbidden,
		Message: message,
		Status:  http.StatusForbidden,
	}
}

// NotFound creates an HTTP 404 Not Found error.
func NotFound(message string) *Error {
	return &Error{
		Code:    CodeNotFound,
		Message: message,
		Status:  http.StatusNotFound,
	}
}

// Conflict creates an HTTP 409 Conflict error.
func Conflict(message string) *Error {
	return &Error{
		Code:    CodeConflict,
		Message: message,
		Status:  http.StatusConflict,
	}
}

// Validation creates an HTTP 422 Unprocessable Entity validation error.
func Validation(message string, violations ...FieldViolation) *Error {
	return &Error{
		Code:    CodeValidation,
		Message: message,
		Status:  http.StatusUnprocessableEntity,
		Details: violations,
	}
}

// RateLimited creates an HTTP 429 Too Many Requests error.
func RateLimited(message string) *Error {
	return &Error{
		Code:    CodeRateLimited,
		Message: message,
		Status:  http.StatusTooManyRequests,
	}
}

// Internal creates an HTTP 500 Internal Server Error with captured stack trace.
func Internal(message string) *Error {
	return &Error{
		Code:    CodeInternal,
		Message: message,
		Status:  http.StatusInternalServerError,
		Stack:   string(debug.Stack()),
	}
}

// String provides a human-readable representation.
func (e *Error) String() string {
	var buf bytes.Buffer
	buf.WriteString(e.Error())
	return buf.String()
}
