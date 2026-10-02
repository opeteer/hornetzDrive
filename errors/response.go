package errors

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// ResponseEnvelope represents the standard REST API envelope structure.
type ResponseEnvelope struct {
	Success bool           `json:"success"`
	Error   *ErrorBody     `json:"error"`
	Meta    map[string]any `json:"meta,omitempty"`
}

// ErrorBody contains the serialized representation of an Error in an envelope.
type ErrorBody struct {
	Code      string           `json:"code"`
	Message   string           `json:"message"`
	Status    int              `json:"status"`
	Details   []FieldViolation `json:"details,omitempty"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
	RequestID string           `json:"request_id,omitempty"`
	TraceID   string           `json:"trace_id,omitempty"`
	Internal  string           `json:"internal,omitempty"`
	Stack     string           `json:"stack,omitempty"`
	Timestamp string           `json:"timestamp"`
}

// ProblemDetails represents an RFC 9457 / RFC 7807 compliant error object.
type ProblemDetails struct {
	Type          string           `json:"type"`
	Title         string           `json:"title"`
	Status        int              `json:"status"`
	Detail        string           `json:"detail"`
	Instance      string           `json:"instance,omitempty"`
	Code          string           `json:"code"`
	InvalidParams []FieldViolation `json:"invalid_params,omitempty"`
	RequestID     string           `json:"request_id,omitempty"`
	TraceID       string           `json:"trace_id,omitempty"`
	Internal      string           `json:"internal,omitempty"`
	Stack         string           `json:"stack,omitempty"`
	Timestamp     string           `json:"timestamp"`
}

// Render writes a standardized error response to the client based on content negotiation and configuration.
func Render(c *echo.Context, appErr *Error, cfg Config) error {
	req := c.Request()
	status := appErr.StatusCode()

	// 1. Content Negotiation: Check whether client prefers HTML or JSON
	accept := req.Header.Get("Accept")
	isHTML := strings.Contains(accept, "text/html") && !strings.HasPrefix(req.URL.Path, "/api/") && !strings.Contains(accept, "application/json")

	if isHTML {
		if cfg.HTMLRenderer != nil {
			return cfg.HTMLRenderer(c, appErr)
		}
		return renderDefaultHTMLError(c, appErr, cfg)
	}

	// 2. JSON Rendering: Check format (Envelope vs ProblemDetails)
	if cfg.Format == FormatProblemDetails {
		c.Response().Header().Set("Content-Type", "application/problem+json; charset=utf-8")
		body := buildProblemDetails(c, appErr, cfg)
		return c.JSON(status, body)
	}

	c.Response().Header().Set("Content-Type", "application/json; charset=utf-8")
	body := buildEnvelope(c, appErr, cfg)
	return c.JSON(status, body)
}

func buildEnvelope(c *echo.Context, appErr *Error, cfg Config) ResponseEnvelope {
	status := appErr.StatusCode()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	msg := appErr.Message

	var internalStr, stackStr string

	if status >= 500 && !cfg.ExposeInternalErrors {
		// Zero-Trust Sanitization: Strip server internals in production
		if appErr.RequestID != "" {
			msg = fmt.Sprintf("%s (Reference ID: %s)", cfg.FallbackMessage, appErr.RequestID)
		} else {
			msg = cfg.FallbackMessage
		}
	} else if cfg.ExposeInternalErrors {
		if appErr.Internal != nil {
			internalStr = appErr.Internal.Error()
		}
		if cfg.EnableStackTrace {
			stackStr = appErr.Stack
		}
	}

	meta := map[string]any{
		"timestamp": timestamp,
	}
	if appErr.RequestID != "" {
		meta["request_id"] = appErr.RequestID
	}
	if appErr.TraceID != "" {
		meta["trace_id"] = appErr.TraceID
	}

	return ResponseEnvelope{
		Success: false,
		Error: &ErrorBody{
			Code:      appErr.Code,
			Message:   msg,
			Status:    status,
			Details:   appErr.Details,
			Metadata:  appErr.Metadata,
			RequestID: appErr.RequestID,
			TraceID:   appErr.TraceID,
			Internal:  internalStr,
			Stack:     stackStr,
			Timestamp: timestamp,
		},
		Meta: meta,
	}
}

func buildProblemDetails(c *echo.Context, appErr *Error, cfg Config) ProblemDetails {
	status := appErr.StatusCode()
	timestamp := time.Now().UTC().Format(time.RFC3339)
	msg := appErr.Message

	var internalStr, stackStr string

	if status >= 500 && !cfg.ExposeInternalErrors {
		if appErr.RequestID != "" {
			msg = fmt.Sprintf("%s (Reference ID: %s)", cfg.FallbackMessage, appErr.RequestID)
		} else {
			msg = cfg.FallbackMessage
		}
	} else if cfg.ExposeInternalErrors {
		if appErr.Internal != nil {
			internalStr = appErr.Internal.Error()
		}
		if cfg.EnableStackTrace {
			stackStr = appErr.Stack
		}
	}

	typeURI := fmt.Sprintf("https://errors.ztatic.dev/codes/%s", strings.ToLower(strings.ReplaceAll(appErr.Code, "_", "-")))

	return ProblemDetails{
		Type:          typeURI,
		Title:         http.StatusText(status),
		Status:        status,
		Detail:        msg,
		Instance:      c.Request().URL.Path,
		Code:          appErr.Code,
		InvalidParams: appErr.Details,
		RequestID:     appErr.RequestID,
		TraceID:       appErr.TraceID,
		Internal:      internalStr,
		Stack:         stackStr,
		Timestamp:     timestamp,
	}
}

var defaultHTMLErrorTemplate = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{{.Status}} - {{.Title}}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; padding: 1.5rem; }
    .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2.5rem; max-width: 520px; width: 100%; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5); }
    .badge { display: inline-block; font-size: 0.875rem; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 9999px; background: #ef4444; color: #ffffff; text-transform: uppercase; margin-bottom: 1rem; }
    h1 { font-size: 1.75rem; margin: 0 0 0.5rem 0; font-weight: 700; }
    p { color: #94a3b8; font-size: 1rem; line-height: 1.5; margin: 0 0 1.5rem 0; }
    .req-id { font-size: 0.75rem; color: #64748b; background: #0f172a; padding: 0.5rem 0.75rem; border-radius: 6px; font-family: monospace; word-break: break-all; margin-bottom: 1.5rem; }
    .btn { display: inline-block; background: #3b82f6; color: white; padding: 0.625rem 1.25rem; border-radius: 6px; font-weight: 600; text-decoration: none; transition: background 0.15s ease-in-out; }
    .btn:hover { background: #2563eb; }
  </style>
</head>
<body>
  <div class="card">
    <div class="badge">{{.Code}}</div>
    <h1>{{.Status}} - {{.Title}}</h1>
    <p>{{.Message}}</p>
    {{if .RequestID}}<div class="req-id">Request ID: {{.RequestID}}</div>{{end}}
    <a href="/" class="btn">Return Home</a>
  </div>
</body>
</html>`))

func renderDefaultHTMLError(c *echo.Context, appErr *Error, cfg Config) error {
	status := appErr.StatusCode()
	msg := appErr.Message

	if status >= 500 && !cfg.ExposeInternalErrors {
		msg = cfg.FallbackMessage
	}

	data := struct {
		Status    int
		Title     string
		Code      string
		Message   string
		RequestID string
	}{
		Status:    status,
		Title:     http.StatusText(status),
		Code:      appErr.Code,
		Message:   msg,
		RequestID: appErr.RequestID,
	}

	c.Response().Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Response().WriteHeader(status)
	return defaultHTMLErrorTemplate.Execute(c.Response(), data)
}
