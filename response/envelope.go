package response

import (
	"encoding/json"
	"reflect"
	"time"

	"ztatic-go-framework/errors"
)

// ResponseMeta contains request-level observability, correlation, and timing metadata.
type ResponseMeta struct {
	RequestID string         `json:"request_id,omitempty"`
	TraceID   string         `json:"trace_id,omitempty"`
	Timestamp string         `json:"timestamp,omitempty"`
	Duration  string         `json:"duration,omitempty"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// Envelope represents a canonical, type-safe REST API response envelope.
// Using Go 1.21+ generics, it guarantees type safety across the application.
type Envelope[T any] struct {
	Success    bool              `json:"success"`
	Data       T                 `json:"data,omitempty"`
	Error      *errors.ErrorBody `json:"error,omitempty"`
	Pagination *PaginationMeta   `json:"pagination,omitempty"`
	Cursor     *CursorMeta       `json:"cursor,omitempty"`
	Meta       *ResponseMeta     `json:"meta,omitempty"`
	Links      *Links            `json:"links,omitempty"`
}

// NewEnvelope initializes a standard successful envelope with the given payload.
func NewEnvelope[T any](data T) *Envelope[T] {
	return &Envelope[T]{
		Success: true,
		Data:    data,
		Meta: &ResponseMeta{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
	}
}

// NewErrorEnvelope creates an error response envelope wrapping an errors.ErrorBody.
func NewErrorEnvelope(errBody *errors.ErrorBody, reqID string, traceID ...string) *Envelope[any] {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	if errBody != nil && errBody.Timestamp != "" {
		timestamp = errBody.Timestamp
	}
	meta := &ResponseMeta{
		RequestID: reqID,
		Timestamp: timestamp,
	}
	if len(traceID) > 0 && traceID[0] != "" {
		meta.TraceID = traceID[0]
	}
	return &Envelope[any]{
		Success: false,
		Error:   errBody,
		Meta:    meta,
	}
}

// MarshalJSON customizes serialization to ensure:
// 1. Data is always present on success (empty slices serialize as [] instead of null).
// 2. Data is omitted on failure, keeping error envelopes clean.
func (e Envelope[T]) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, 6)
	m["success"] = e.Success

	if e.Success {
		m["data"] = sanitizeEmptySlice(e.Data)
	}
	if e.Error != nil {
		m["error"] = e.Error
	}
	if e.Pagination != nil {
		m["pagination"] = e.Pagination
	}
	if e.Cursor != nil {
		m["cursor"] = e.Cursor
	}
	if e.Meta != nil {
		m["meta"] = e.Meta
	}
	if e.Links != nil {
		m["links"] = e.Links
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements custom unmarshaling for Envelope[T].
func (e *Envelope[T]) UnmarshalJSON(b []byte) error {
	type Alias Envelope[T]
	aux := &struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	}
	return json.Unmarshal(b, aux)
}

// sanitizeEmptySlice ensures that nil or uninitialized slices serialize as [] rather than null in JSON.
func sanitizeEmptySlice(data any) any {
	val := reflect.ValueOf(data)
	if !val.IsValid() {
		return data
	}
	if val.Kind() == reflect.Slice && val.IsNil() {
		return reflect.MakeSlice(val.Type(), 0, 0).Interface()
	}
	return data
}
