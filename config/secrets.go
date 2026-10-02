package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"ztatic-go-framework/security/crypto"
	"ztatic-go-framework/security/privacy"
)

// RedactedPlaceholder is the default string representation for sensitive secrets.
const RedactedPlaceholder = "[REDACTED]"

// SecretString provides an opaque wrapper around sensitive string values
// such as API keys, passwords, tokens, and cryptographic secrets.
//
// By default, it masks its value when serialized to JSON, formatted via fmt,
// or logged via slog. To access the underlying plaintext value, call Expose().
type SecretString struct {
	data []byte
	mu   sync.RWMutex
}

// NewSecretString initializes a new SecretString with the provided plaintext.
func NewSecretString(val string) SecretString {
	return SecretString{data: []byte(val)}
}

// Expose returns the underlying sensitive plaintext string.
// Use this with intention when passing credentials to database drivers,
// cryptographic suites, or external APIs.
func (s *SecretString) Expose() string {
	if s == nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return string(s.data)
}

// Value is an alias for Expose to satisfy getter conventions.
func (s *SecretString) Value() string {
	return s.Expose()
}

// IsEmpty reports whether the underlying secret is empty.
func (s *SecretString) IsEmpty() bool {
	if s == nil {
		return true
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data) == 0
}

// Destroy securely overwrites the in-memory string bytes with zeros
// using privacy.Zeroize, mitigating risks of heap dumps or panics.
func (s *SecretString) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.data) > 0 {
		privacy.Zeroize(s.data)
		s.data = nil
	}
}

// String implements fmt.Stringer to ensure %s and %v print [REDACTED].
func (s SecretString) String() string {
	return RedactedPlaceholder
}

// GoString implements fmt.GoStringer to ensure %#v prints [REDACTED].
func (s SecretString) GoString() string {
	return RedactedPlaceholder
}

// MarshalJSON implements json.Marshaler to prevent leaking secrets in JSON payloads.
func (s SecretString) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedPlaceholder)
}

// UnmarshalJSON implements json.Unmarshaler to populate the secret from JSON.
func (s *SecretString) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	s.mu.Lock()
	s.data = []byte(raw)
	s.mu.Unlock()
	return nil
}

// LogValue implements slog.LogValuer to ensure zero-leak logging with slog.
func (s SecretString) LogValue() slog.Value {
	return slog.StringValue(RedactedPlaceholder)
}

// UnmarshalText implements encoding.TextUnmarshaler.
func (s *SecretString) UnmarshalText(text []byte) error {
	s.mu.Lock()
	s.data = append([]byte(nil), text...)
	s.mu.Unlock()
	return nil
}

// Secret provides a generic container wrapping any arbitrary sensitive value.
type Secret[T any] struct {
	value T
	mu    sync.RWMutex
}

// NewSecret creates a new generic Secret container.
func NewSecret[T any](val T) Secret[T] {
	return Secret[T]{value: val}
}

// Expose returns the wrapped sensitive value.
func (s *Secret[T]) Expose() T {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.value
}

// String implements fmt.Stringer.
func (s Secret[T]) String() string {
	return RedactedPlaceholder
}

// GoString implements fmt.GoStringer.
func (s Secret[T]) GoString() string {
	return RedactedPlaceholder
}

// MarshalJSON implements json.Marshaler.
func (s Secret[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(RedactedPlaceholder)
}

// LogValue implements slog.LogValuer.
func (s Secret[T]) LogValue() slog.Value {
	return slog.StringValue(RedactedPlaceholder)
}

// ResolveSecret resolves a raw environment variable or configuration string:
// 1. If prefix is "file://", loads secret content from the referenced file path (e.g. Kubernetes/Docker secrets).
// 2. If prefix is "enc:aes-gcm:", decrypts using the provided cipher suite (or framework default).
// 3. Otherwise returns raw trimmed string.
func ResolveSecret(raw string, cs *crypto.CipherSuite) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}

	// 1. File-based secret: file:///path/to/secret
	if strings.HasPrefix(trimmed, "file://") {
		filePath := strings.TrimPrefix(trimmed, "file://")
		content, err := os.ReadFile(filePath)
		if err != nil {
			return "", fmt.Errorf("failed to read file secret at %q: %w", filePath, err)
		}
		return strings.TrimSpace(string(content)), nil
	}

	// 2. Encrypted secret: enc:aes-gcm:<ciphertext>
	const encPrefix = "enc:aes-gcm:"
	if strings.HasPrefix(trimmed, encPrefix) {
		ciphertext := strings.TrimPrefix(trimmed, encPrefix)
		suite := cs
		if suite == nil {
			suite = crypto.GetDefaultCipherSuite()
		}
		if suite == nil {
			return "", fmt.Errorf("cannot decrypt %q: no cipher suite configured (set ZTATIC_CIPHER_KEY or provide CipherSuite)", trimmed)
		}
		decrypted, err := suite.Decrypt(ciphertext)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt encrypted secret: %w", err)
		}
		return decrypted, nil
	}

	return trimmed, nil
}
