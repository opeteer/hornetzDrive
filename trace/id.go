package trace

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync/atomic"
	"time"
)

var reqCounter uint64

// GenerateRequestID generates a URL-safe, collision-resistant, timestamped request ID.
func GenerateRequestID() string {
	seq := atomic.AddUint64(&reqCounter, 1)
	randomBytes := make([]byte, 4)
	_, _ = rand.Read(randomBytes)
	return fmt.Sprintf("req-%x-%x-%04x", time.Now().UnixNano(), randomBytes, seq%0xffff)
}

// GenerateTraceID generates a 16-byte (32-hex character) distributed trace ID.
func GenerateTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	// Guard against astronomically rare all-zero
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		b[0] = 1
	}
	return hex.EncodeToString(b)
}

// GenerateSpanID generates an 8-byte (16-hex character) span ID.
func GenerateSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	// Guard against all-zero
	if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
		b[0] = 1
	}
	return hex.EncodeToString(b)
}

// SanitizeID validates and cleans an untrusted external ID (such as an incoming X-Request-ID).
// It prevents HTTP Response Splitting (CRLF injection), log injection, and memory bloat.
// Returns the sanitized ID, or empty string if the ID is invalid or malformed.
func SanitizeID(raw string, maxLen int) string {
	if maxLen <= 0 {
		maxLen = 128
	}

	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || len(trimmed) > maxLen {
		return ""
	}

	// Validate character set: ASCII printable only, no control chars or CRLF
	for i := 0; i < len(trimmed); i++ {
		b := trimmed[i]
		// Disallow control characters (< 32), DEL (127), and extended non-ASCII (> 127)
		if b < 32 || b >= 127 {
			return ""
		}

		// Allow alphanumeric and common safe punctuation: - _ . / @ = + :
		isAlphaNum := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
		isSafePunct := b == '-' || b == '_' || b == '.' || b == '/' || b == '@' || b == '=' || b == '+' || b == ':'
		if !isAlphaNum && !isSafePunct {
			return ""
		}
	}

	return trimmed
}
