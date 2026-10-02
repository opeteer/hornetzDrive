package errors

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sync"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// DefaultCanonicalStatuses defines the default HTTP status codes for standard error codes.
var DefaultCanonicalStatuses = map[string]int{
	CodeBadRequest:         http.StatusBadRequest,
	CodeUnauthorized:       http.StatusUnauthorized,
	CodeForbidden:          http.StatusForbidden,
	CodeNotFound:           http.StatusNotFound,
	CodeConflict:           http.StatusConflict,
	CodeValidation:         http.StatusUnprocessableEntity,
	CodePayloadTooLarge:    http.StatusRequestEntityTooLarge,
	CodeUnsupportedMedia:   http.StatusUnsupportedMediaType,
	CodeRateLimited:        http.StatusTooManyRequests,
	CodeClientClosed:       499, // Client Closed Request (nginx / standard convention)
	CodeInternal:           http.StatusInternalServerError,
	CodeNotImplemented:     http.StatusNotImplemented,
	CodeBadGateway:         http.StatusBadGateway,
	CodeServiceUnavailable: http.StatusServiceUnavailable,
	CodeGatewayTimeout:     http.StatusGatewayTimeout,
}

// CanonicalStatus returns the standard HTTP status code for a given error code,
// defaulting to 500 Internal Server Error if unmapped.
func CanonicalStatus(code string) int {
	if status, ok := DefaultCanonicalStatuses[code]; ok {
		return status
	}
	return http.StatusInternalServerError
}

// TypeMatcherFunc inspects an arbitrary error and returns true if it matches a custom type.
type TypeMatcherFunc func(err error) bool

// ErrorTransformerFunc converts a matched error into a standardized *Error.
type ErrorTransformerFunc func(err error) *Error

type customTypeMapping struct {
	matcher     TypeMatcherFunc
	transformer ErrorTransformerFunc
}

// Mapper translates arbitrary application, runtime, and third-party errors into standardized *Error instances.
type Mapper struct {
	mu           sync.RWMutex
	codeStatuses map[string]int
	exactErrors  map[error]*Error
	typeMappings []customTypeMapping
}

// NewMapper initializes a new error mapper pre-configured with default standard mappings.
func NewMapper() *Mapper {
	m := &Mapper{
		codeStatuses: make(map[string]int),
		exactErrors:  make(map[error]*Error),
		typeMappings: make([]customTypeMapping, 0),
	}
	// Copy default canonical statuses
	for k, v := range DefaultCanonicalStatuses {
		m.codeStatuses[k] = v
	}

	// Register built-in standard library & runtime error mappings
	m.RegisterExact(sql.ErrNoRows, NotFound("Record not found").WithInternal(sql.ErrNoRows))
	m.RegisterExact(os.ErrNotExist, NotFound("File or resource not found").WithInternal(os.ErrNotExist))
	m.RegisterExact(os.ErrPermission, Forbidden("Permission denied").WithInternal(os.ErrPermission))
	m.RegisterExact(context.Canceled, &Error{
		Code:     CodeClientClosed,
		Message:  "Client cancelled request",
		Status:   499,
		Internal: context.Canceled,
	})
	m.RegisterExact(context.DeadlineExceeded, &Error{
		Code:     CodeGatewayTimeout,
		Message:  "Request processing timed out",
		Status:   http.StatusGatewayTimeout,
		Internal: context.DeadlineExceeded,
	})

	return m
}

// RegisterExact registers a mapping for an exact sentinel error using errors.Is comparison.
func (m *Mapper) RegisterExact(target error, appErr *Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.exactErrors[target] = appErr
}

// RegisterType registers a dynamic type matcher and conversion function.
func (m *Mapper) RegisterType(matcher TypeMatcherFunc, transformer ErrorTransformerFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.typeMappings = append(m.typeMappings, customTypeMapping{
		matcher:     matcher,
		transformer: transformer,
	})
}

// RegisterCode configures or overrides the HTTP status mapping for an error code.
func (m *Mapper) RegisterCode(code string, status int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codeStatuses[code] = status
}

// Map inspects any error and converts it into a standardized *Error.
func (m *Mapper) Map(err error) *Error {
	if err == nil {
		return nil
	}

	// 1. If it's already an *Error, ensure status code is resolved
	var existingAppErr *Error
	if errors.As(err, &existingAppErr) {
		res := existingAppErr.Clone()
		if res.Status == 0 {
			m.mu.RLock()
			status, ok := m.codeStatuses[res.Code]
			m.mu.RUnlock()
			if ok {
				res.Status = status
			} else {
				res.Status = CanonicalStatus(res.Code)
			}
		}
		return res
	}

	// 2. Check exact sentinel errors (errors.Is)
	m.mu.RLock()
	for target, mapped := range m.exactErrors {
		if errors.Is(err, target) {
			m.mu.RUnlock()
			res := mapped.Clone()
			res.Internal = err
			return res
		}
	}

	// 3. Check custom registered type mappings
	for _, mapping := range m.typeMappings {
		if mapping.matcher(err) {
			m.mu.RUnlock()
			return mapping.transformer(err)
		}
	}
	m.mu.RUnlock()

	// 4. Handle validator.ValidationErrors (struct validation failures)
	var valErrors validator.ValidationErrors
	if errors.As(err, &valErrors) {
		violations := make([]FieldViolation, 0, len(valErrors))
		for _, fe := range valErrors {
			msg := formatValidationRule(fe)
			violations = append(violations, FieldViolation{
				Field:   fe.Field(),
				Rule:    fe.Tag(),
				Message: msg,
				Value:   fe.Value(),
			})
		}
		return Validation(fmt.Sprintf("Validation failed on %d field(s)", len(violations)), violations...).
			WithInternal(err)
	}

	// 5. Handle Echo Recover PanicStackError
	var panicErr *middleware.PanicStackError
	if errors.As(err, &panicErr) {
		appErr := Internal("A critical server panic occurred").
			WithInternal(panicErr.Err)
		appErr.Stack = string(panicErr.Stack)
		return appErr
	}

	// 6. Handle Echo v5 *echo.HTTPError
	var httpErr *echo.HTTPError
	if errors.As(err, &httpErr) {
		msg := httpErr.Message
		if msg == "" {
			msg = http.StatusText(httpErr.Code)
		}
		code := codeFromStatus(httpErr.Code)
		appErr := &Error{
			Code:     code,
			Message:  msg,
			Status:   httpErr.Code,
			Internal: httpErr.Unwrap(),
		}
		return appErr
	}

	// 6. Check if error satisfies echo.HTTPStatusCoder
	var sc echo.HTTPStatusCoder
	if errors.As(err, &sc) {
		status := sc.StatusCode()
		if status != 0 {
			code := codeFromStatus(status)
			return &Error{
				Code:     code,
				Message:  err.Error(),
				Status:   status,
				Internal: err,
			}
		}
	}

	// 7. Fallback: Wrap as internal server error
	return Internal("An unexpected internal error occurred").
		WithInternal(err)
}

// formatValidationRule formats a go-playground/validator error into a clean message.
func formatValidationRule(fe validator.FieldError) string {
	field := fe.Field()
	switch fe.Tag() {
	case "required":
		return fmt.Sprintf("Field '%s' is required", field)
	case "email":
		return fmt.Sprintf("Field '%s' must be a valid email address", field)
	case "min":
		return fmt.Sprintf("Field '%s' must be at least %s in length or value", field, fe.Param())
	case "max":
		return fmt.Sprintf("Field '%s' must be at most %s in length or value", field, fe.Param())
	case "len":
		return fmt.Sprintf("Field '%s' must be exactly %s in length", field, fe.Param())
	case "alphanum":
		return fmt.Sprintf("Field '%s' must be alphanumeric", field)
	case "url":
		return fmt.Sprintf("Field '%s' must be a valid URL", field)
	case "uuid":
		return fmt.Sprintf("Field '%s' must be a valid UUID", field)
	default:
		if fe.Param() != "" {
			return fmt.Sprintf("Field '%s' failed on '%s' rule with parameter '%s'", field, fe.Tag(), fe.Param())
		}
		return fmt.Sprintf("Field '%s' failed on '%s' validation tag", field, fe.Tag())
	}
}

// codeFromStatus derives an appropriate Code slug from an HTTP status code.
func codeFromStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return CodeBadRequest
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusConflict:
		return CodeConflict
	case http.StatusUnprocessableEntity:
		return CodeValidation
	case http.StatusRequestEntityTooLarge:
		return CodePayloadTooLarge
	case http.StatusUnsupportedMediaType:
		return CodeUnsupportedMedia
	case http.StatusTooManyRequests:
		return CodeRateLimited
	case http.StatusNotImplemented:
		return CodeNotImplemented
	case http.StatusBadGateway:
		return CodeBadGateway
	case http.StatusServiceUnavailable:
		return CodeServiceUnavailable
	case http.StatusGatewayTimeout:
		return CodeGatewayTimeout
	default:
		if status >= 400 && status < 500 {
			return CodeBadRequest
		}
		return CodeInternal
	}
}

// DefaultMapper is the framework's global default error mapper.
var DefaultMapper = NewMapper()

// Map maps an error using DefaultMapper.
func Map(err error) *Error {
	return DefaultMapper.Map(err)
}

// RegisterMapping registers an exact sentinel error mapping onto DefaultMapper.
func RegisterMapping(target error, appErr *Error) {
	DefaultMapper.RegisterExact(target, appErr)
}

// RegisterTypeMapping registers a type matcher onto DefaultMapper.
func RegisterTypeMapping(matcher TypeMatcherFunc, transformer ErrorTransformerFunc) {
	DefaultMapper.RegisterType(matcher, transformer)
}

// RegisterCode configures the HTTP status code for an error code on DefaultMapper.
func RegisterCode(code string, status int) {
	DefaultMapper.RegisterCode(code, status)
}
