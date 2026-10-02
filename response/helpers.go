package response

import (
	"net/http"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/errors"
	"ztatic-go-framework/trace"
)

// Option specifies customization options for response envelopes.
type Option func(*envelopeOptions)

type envelopeOptions struct {
	customMeta map[string]any
	links      *Links
	headers    map[string]string
	reqID      string
	traceID    string
}

// WithMeta adds a single custom key-value pair to response metadata.
func WithMeta(key string, value any) Option {
	return func(o *envelopeOptions) {
		if o.customMeta == nil {
			o.customMeta = make(map[string]any)
		}
		o.customMeta[key] = value
	}
}

// WithCustomMeta merges an existing map into response metadata.
func WithCustomMeta(m map[string]any) Option {
	return func(o *envelopeOptions) {
		if o.customMeta == nil {
			o.customMeta = make(map[string]any)
		}
		for k, v := range m {
			o.customMeta[k] = v
		}
	}
}

// WithLinks overrides the HATEOAS navigation links on the envelope.
func WithLinks(links *Links) Option {
	return func(o *envelopeOptions) {
		o.links = links
	}
}

// WithHeader attaches an arbitrary HTTP header to the response.
func WithHeader(key, value string) Option {
	return func(o *envelopeOptions) {
		if o.headers == nil {
			o.headers = make(map[string]string)
		}
		o.headers[key] = value
	}
}

// WithRequestID explicitly sets the request correlation ID on the envelope.
func WithRequestID(reqID string) Option {
	return func(o *envelopeOptions) {
		o.reqID = reqID
	}
}

// WithTraceID explicitly sets the distributed trace ID on the envelope.
func WithTraceID(traceID string) Option {
	return func(o *envelopeOptions) {
		o.traceID = traceID
	}
}

// OK renders a standard HTTP 200 envelope with the provided data payload.
func OK(c *echo.Context, data any, opts ...Option) error {
	return JSON(c, http.StatusOK, data, opts...)
}

// Created renders an HTTP 201 envelope. If a location URI is provided,
// it sets the HTTP Location header.
func Created(c *echo.Context, data any, location ...string) error {
	var opts []Option
	if len(location) > 0 && location[0] != "" {
		opts = append(opts, WithHeader("Location", location[0]))
	}
	return JSON(c, http.StatusCreated, data, opts...)
}

// Accepted renders an HTTP 202 Accepted envelope.
func Accepted(c *echo.Context, data any, opts ...Option) error {
	return JSON(c, http.StatusAccepted, data, opts...)
}

// NoContent renders an HTTP 204 No Content response with an empty body.
func NoContent(c *echo.Context) error {
	return c.NoContent(http.StatusNoContent)
}

// Paginated renders an HTTP 200 envelope for a paginated slice collection.
// It automatically calculates and embeds HATEOAS links and sets the standard RFC 5988 Link header.
func Paginated[T any](c *echo.Context, items []T, meta *PaginationMeta, opts ...Option) error {
	envOpts := applyOptions(opts)
	applyHeaders(c, envOpts.headers)

	reqID := envOpts.reqID
	if reqID == "" {
		reqID = resolveRequestID(c)
	}

	links := envOpts.links
	if links == nil && meta != nil {
		links = GenerateLinks(c, meta.Page, meta.PerPage, meta.TotalPages)
	}
	if links != nil {
		SetLinkHeader(c, links)
	}

	traceID := envOpts.traceID
	if traceID == "" {
		traceID = resolveTraceID(c)
	}

	respMeta := &ResponseMeta{
		RequestID: reqID,
		TraceID:   traceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Duration:  resolveDuration(c),
		Extra:     envOpts.customMeta,
	}

	env := &Envelope[[]T]{
		Success:    true,
		Data:       items,
		Pagination: meta,
		Meta:       respMeta,
		Links:      links,
	}

	return c.JSON(http.StatusOK, env)
}

// CursorPaginated renders an HTTP 200 envelope for a cursor-paginated slice collection.
func CursorPaginated[T any](c *echo.Context, items []T, meta *CursorMeta, opts ...Option) error {
	envOpts := applyOptions(opts)
	applyHeaders(c, envOpts.headers)

	reqID := envOpts.reqID
	if reqID == "" {
		reqID = resolveRequestID(c)
	}

	traceID := envOpts.traceID
	if traceID == "" {
		traceID = resolveTraceID(c)
	}

	respMeta := &ResponseMeta{
		RequestID: reqID,
		TraceID:   traceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Duration:  resolveDuration(c),
		Extra:     envOpts.customMeta,
	}

	env := &Envelope[[]T]{
		Success: true,
		Data:    items,
		Cursor:  meta,
		Meta:    respMeta,
	}

	return c.JSON(http.StatusOK, env)
}

// JSON renders a standardized envelope with any HTTP status code.
func JSON(c *echo.Context, status int, data any, opts ...Option) error {
	envOpts := applyOptions(opts)
	applyHeaders(c, envOpts.headers)

	reqID := envOpts.reqID
	if reqID == "" {
		reqID = resolveRequestID(c)
	}

	traceID := envOpts.traceID
	if traceID == "" {
		traceID = resolveTraceID(c)
	}

	respMeta := &ResponseMeta{
		RequestID: reqID,
		TraceID:   traceID,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Duration:  resolveDuration(c),
		Extra:     envOpts.customMeta,
	}

	env := &Envelope[any]{
		Success: status >= 200 && status < 300,
		Data:    data,
		Meta:    respMeta,
		Links:   envOpts.links,
	}

	return c.JSON(status, env)
}

// Error maps and renders an error into the framework's standardized error response.
func Error(c *echo.Context, err error) error {
	if err == nil {
		return nil
	}
	appErr := errors.DefaultMapper.Map(err)
	if appErr.RequestID == "" {
		appErr.RequestID = resolveRequestID(c)
	}
	if appErr.TraceID == "" {
		appErr.TraceID = resolveTraceID(c)
	}
	return errors.Render(c, appErr, errors.DefaultConfig())
}

// Raw provides an escape hatch to emit raw, un-enveloped JSON (useful for webhooks or external consumers).
func Raw(c *echo.Context, status int, data any) error {
	return c.JSON(status, data)
}

// ContextKeyStartTime is the context key for recording request initiation timestamp.
const ContextKeyStartTime = "_ztatic_req_start_time"

func resolveRequestID(c *echo.Context) string {
	if c == nil {
		return ""
	}
	if req := c.Request(); req != nil {
		if reqID := trace.RequestID(req.Context()); reqID != "" {
			return reqID
		}
	}
	if reqID := c.Response().Header().Get(echo.HeaderXRequestID); reqID != "" {
		return reqID
	}
	if reqID := c.Response().Header().Get("X-Request-Id"); reqID != "" {
		return reqID
	}
	if req := c.Request(); req != nil {
		if reqID := req.Header.Get(echo.HeaderXRequestID); reqID != "" {
			return reqID
		}
	}
	if val, ok := c.Get("request_id").(string); ok && val != "" {
		return val
	}
	return ""
}

func resolveTraceID(c *echo.Context) string {
	if c == nil {
		return ""
	}
	if req := c.Request(); req != nil {
		if traceID := trace.TraceID(req.Context()); traceID != "" {
			return traceID
		}
	}
	if val, ok := c.Get("trace_id").(string); ok && val != "" {
		return val
	}
	if tp := c.Response().Header().Get(trace.HeaderTraceparent); tp != "" {
		if tID, _, _, err := trace.ParseTraceparent(tp); err == nil {
			return tID
		}
	}
	if req := c.Request(); req != nil {
		if tp := req.Header.Get(trace.HeaderTraceparent); tp != "" {
			if tID, _, _, err := trace.ParseTraceparent(tp); err == nil {
				return tID
			}
		}
	}
	return ""
}

func resolveDuration(c *echo.Context) string {
	if c == nil {
		return ""
	}
	if val := c.Get(ContextKeyStartTime); val != nil {
		if startTime, ok := val.(time.Time); ok {
			return time.Since(startTime).String()
		}
	}
	return ""
}

func applyOptions(opts []Option) envelopeOptions {
	var o envelopeOptions
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

func applyHeaders(c *echo.Context, headers map[string]string) {
	if c == nil || headers == nil {
		return
	}
	resHeader := c.Response().Header()
	for k, v := range headers {
		resHeader.Set(k, v)
	}
}
