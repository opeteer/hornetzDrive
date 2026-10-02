package config

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ztatic-go-framework/security/crypto"
)

func TestSecretString_Masking(t *testing.T) {
	secretVal := "super-sensitive-api-key-12345"
	s := NewSecretString(secretVal)

	// Expose
	if s.Expose() != secretVal {
		t.Errorf("Expose() = %q; want %q", s.Expose(), secretVal)
	}
	if s.Value() != secretVal {
		t.Errorf("Value() = %q; want %q", s.Value(), secretVal)
	}

	// fmt.Stringer
	formatted := fmt.Sprintf("%s", s)
	if formatted != RedactedPlaceholder {
		t.Errorf("fmt.Sprintf(%%s) = %q; want %q", formatted, RedactedPlaceholder)
	}
	formattedV := fmt.Sprintf("%v", s)
	if formattedV != RedactedPlaceholder {
		t.Errorf("fmt.Sprintf(%%v) = %q; want %q", formattedV, RedactedPlaceholder)
	}

	// fmt.GoStringer
	goFormatted := fmt.Sprintf("%#v", s)
	if goFormatted != RedactedPlaceholder {
		t.Errorf("fmt.Sprintf(%%#v) = %q; want %q", goFormatted, RedactedPlaceholder)
	}

	// json.Marshal
	jsonData, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}
	if string(jsonData) != `"[REDACTED]"` {
		t.Errorf("json.Marshal = %s; want %s", string(jsonData), `"[REDACTED]"`)
	}

	// slog
	logVal := s.LogValue()
	if logVal.Kind() != slog.KindString || logVal.String() != RedactedPlaceholder {
		t.Errorf("LogValue() = %v; want %s", logVal, RedactedPlaceholder)
	}
}

func TestSecretString_Zeroize(t *testing.T) {
	s := NewSecretString("top-secret-token")
	if s.IsEmpty() {
		t.Fatal("expected secret not to be empty")
	}

	s.Destroy()

	if !s.IsEmpty() {
		t.Errorf("expected secret to be empty after Destroy(), got len %d", len(s.Expose()))
	}
	if s.Expose() != "" {
		t.Errorf("expected empty string after Destroy, got %q", s.Expose())
	}
}

func TestResolveSecret_File(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "password.txt")
	expectedContent := "db-admin-password-xyz!"
	if err := os.WriteFile(secretFile, []byte(expectedContent+"\n"), 0600); err != nil {
		t.Fatalf("failed to write secret file: %v", err)
	}

	resolved, err := ResolveSecret("file://"+secretFile, nil)
	if err != nil {
		t.Fatalf("ResolveSecret failed: %v", err)
	}
	if resolved != expectedContent {
		t.Errorf("ResolveSecret() = %q; want %q", resolved, expectedContent)
	}
}

func TestResolveSecret_Encrypted(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	cs, err := crypto.NewCipherSuite(key)
	if err != nil {
		t.Fatalf("failed to create cipher suite: %v", err)
	}

	plaintext := "sensitive-database-password"
	ciphertext, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("failed to encrypt: %v", err)
	}

	encString := "enc:aes-gcm:" + ciphertext
	resolved, err := ResolveSecret(encString, cs)
	if err != nil {
		t.Fatalf("ResolveSecret failed: %v", err)
	}
	if resolved != plaintext {
		t.Errorf("ResolveSecret() = %q; want %q", resolved, plaintext)
	}

	// Test without cipher suite returns error
	crypto.SetDefaultCipherSuite(nil)
	_, err = ResolveSecret(encString, nil)
	if err == nil {
		t.Error("expected error when decrypting without cipher suite")
	} else if !strings.Contains(err.Error(), "no cipher suite configured") {
		t.Errorf("unexpected error message: %v", err)
	}
}
