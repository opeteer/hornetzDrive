package response

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/labstack/echo/v5"
)

// CursorParams captures cursor-based query parameters from an incoming request.
type CursorParams struct {
	Cursor    string
	Limit     int
	Direction string
}

// CursorMeta models cursor pagination output metadata.
type CursorMeta struct {
	Cursor     string `json:"cursor,omitempty"`
	NextCursor string `json:"next_cursor,omitempty"`
	PrevCursor string `json:"prev_cursor,omitempty"`
	Limit      int    `json:"limit"`
	HasMore    bool   `json:"has_more"`
}

// CursorOption defines functional options for ExtractCursor.
type CursorOption func(*cursorOptions)

type cursorOptions struct {
	defaultLimit int
	maxLimit     int
}

// WithDefaultLimit sets a fallback limit for cursor pagination.
func WithDefaultLimit(limit int) CursorOption {
	return func(o *cursorOptions) {
		if limit > 0 {
			o.defaultLimit = limit
		}
	}
}

// WithMaxLimit sets the maximum allowed cursor query limit.
func WithMaxLimit(max int) CursorOption {
	return func(o *cursorOptions) {
		if max > 0 {
			o.maxLimit = max
		}
	}
}

// ExtractCursor extracts cursor parameters from the request query string.
func ExtractCursor(c *echo.Context, opts ...CursorOption) CursorParams {
	cfg := cursorOptions{
		defaultLimit: 20,
		maxLimit:     100,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	cursor := strings.TrimSpace(c.QueryParam("cursor"))

	limit := cfg.defaultLimit
	rawLimit := c.QueryParam("limit")
	if rawLimit == "" {
		rawLimit = c.QueryParam("per_page")
	}
	if rawLimit != "" {
		if val, err := strconv.Atoi(rawLimit); err == nil && val > 0 {
			limit = val
		}
	}
	if limit > cfg.maxLimit {
		limit = cfg.maxLimit
	}

	direction := strings.ToLower(strings.TrimSpace(c.QueryParam("direction")))
	if direction == "" {
		direction = strings.ToLower(strings.TrimSpace(c.QueryParam("dir")))
	}
	if direction != "prev" {
		direction = "next"
	}

	return CursorParams{
		Cursor:    cursor,
		Limit:     limit,
		Direction: direction,
	}
}

// EncodeCursor marshals any value to JSON and produces a URL-safe Base64 token.
func EncodeCursor(v any) (string, error) {
	if v == nil {
		return "", nil
	}
	data, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("response: failed to marshal cursor payload: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeCursor decodes a URL-safe Base64 token and unmarshals it into type T.
func DecodeCursor[T any](raw string) (*T, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}

	// Support both standard URLEncoding and RawURLEncoding
	data, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("response: invalid cursor encoding: %w", err)
		}
	}

	var target T
	if err := json.Unmarshal(data, &target); err != nil {
		return nil, fmt.Errorf("response: invalid cursor json payload: %w", err)
	}

	return &target, nil
}
