package trace

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidTraceparentLength = errors.New("traceparent header has invalid length")
	ErrInvalidTraceparentFormat = errors.New("traceparent header format is malformed")
	ErrUnsupportedVersion       = errors.New("unsupported traceparent version")
	ErrAllZeroTraceID           = errors.New("trace_id cannot be all zeros")
	ErrAllZeroSpanID            = errors.New("span_id cannot be all zeros")
	ErrInvalidHexCharacters     = errors.New("traceparent contains invalid hex characters")
)

const (
	w3cVersion00 = "00"
	allZeroTrace = "00000000000000000000000000000000"
	allZeroSpan  = "0000000000000000"
)

// ParseTraceparent parses a W3C traceparent header string (e.g., "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").
// It enforces W3C Recommendation validation rules including version check, non-zero IDs, and hex encoding.
func ParseTraceparent(header string) (traceID string, parentID string, sampled bool, err error) {
	header = strings.TrimSpace(header)
	if len(header) < 55 {
		return "", "", false, ErrInvalidTraceparentLength
	}

	parts := strings.Split(header, "-")
	if len(parts) < 4 {
		return "", "", false, ErrInvalidTraceparentFormat
	}

	version := parts[0]
	if len(version) != 2 || version == "ff" {
		return "", "", false, ErrUnsupportedVersion
	}

	// For version 00, length must be exactly 55 characters and exactly 4 parts
	if version == w3cVersion00 {
		if len(header) != 55 || len(parts) != 4 {
			return "", "", false, ErrInvalidTraceparentFormat
		}
	}

	rawTraceID := strings.ToLower(parts[1])
	rawParentID := strings.ToLower(parts[2])
	rawFlags := parts[3]

	if len(rawTraceID) != 32 {
		return "", "", false, ErrInvalidTraceparentFormat
	}
	if rawTraceID == allZeroTrace {
		return "", "", false, ErrAllZeroTraceID
	}
	if _, err := hex.DecodeString(rawTraceID); err != nil {
		return "", "", false, ErrInvalidHexCharacters
	}

	if len(rawParentID) != 16 {
		return "", "", false, ErrInvalidTraceparentFormat
	}
	if rawParentID == allZeroSpan {
		return "", "", false, ErrAllZeroSpanID
	}
	if _, err := hex.DecodeString(rawParentID); err != nil {
		return "", "", false, ErrInvalidHexCharacters
	}

	if len(rawFlags) != 2 {
		return "", "", false, ErrInvalidTraceparentFormat
	}
	flagBytes, err := hex.DecodeString(rawFlags)
	if err != nil {
		return "", "", false, ErrInvalidHexCharacters
	}

	// Bit 0 indicates recorded/sampled
	isSampled := (flagBytes[0] & 0x01) == 0x01

	return rawTraceID, rawParentID, isSampled, nil
}

// FormatTraceparent constructs a W3C traceparent header string from traceID, spanID, and sampled flag.
func FormatTraceparent(traceID, spanID string, sampled bool) string {
	flags := "00"
	if sampled {
		flags = "01"
	}
	return fmt.Sprintf("%s-%s-%s-%s", w3cVersion00, traceID, spanID, flags)
}
