package privacy

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

func TestLogMasker_RedactsSensitiveData(t *testing.T) {
	var buf bytes.Buffer
	baseHandler := slog.NewTextHandler(&buf, nil)
	masker := NewLogMasker(baseHandler)
	logger := slog.New(masker)

	logger.Info("User login attempt",
		"username", "john_doe",
		"password", "SuperSecret123!",
		"ssn", "000-11-2222",
	)

	output := buf.String()

	if !strings.Contains(output, "username=john_doe") {
		t.Errorf("non-sensitive field 'username' was missing or altered")
	}

	if strings.Contains(output, "SuperSecret123!") {
		t.Errorf("sensitive field 'password' leaked into logs!")
	}

	if strings.Contains(output, "000-11-2222") {
		t.Errorf("sensitive field 'ssn' leaked into logs!")
	}

	if !strings.Contains(output, "password=[REDACTED]") {
		t.Errorf("expected redacted password attribute, got output: %s", output)
	}

	_ = context.Background()
}

func TestSanitizeMap(t *testing.T) {
	input := map[string]any{
		"user": "alice",
		"password": "my-secret-password",
		"nested": map[string]any{
			"api_key": "sk-1234567890",
			"score": 100,
		},
		"tags": []any{
			"public",
			map[string]any{"token": "bearer-token-val", "id": 1},
		},
	}

	sanitized := SanitizeMap(input)

	if sanitized["user"] != "alice" {
		t.Errorf("expected user to be alice, got %v", sanitized["user"])
	}
	if sanitized["password"] != RedactedString {
		t.Errorf("expected password to be redacted, got %v", sanitized["password"])
	}

	nested, ok := sanitized["nested"].(map[string]any)
	if !ok || nested["api_key"] != RedactedString || nested["score"] != 100 {
		t.Errorf("nested map not sanitized properly: %v", nested)
	}

	tags, ok := sanitized["tags"].([]any)
	if !ok || len(tags) != 2 {
		t.Fatalf("tags slice invalid: %v", sanitized["tags"])
	}
	tagMap, ok := tags[1].(map[string]any)
	if !ok || tagMap["token"] != RedactedString || tagMap["id"] != 1 {
		t.Errorf("slice item map not sanitized properly: %v", tagMap)
	}

	// Verify original was not mutated in place
	if input["password"] == RedactedString {
		t.Errorf("input map was mutated in place")
	}
}

func TestIsSensitiveKey(t *testing.T) {
	cases := []struct {
		key      string
		expected bool
	}{
		{"password", true},
		{"PASSWORD", true},
		{"user_password", true},
		{"api_key", true},
		{"authorization", true},
		{"token", true},
		{"credit_card", true},
		{"username", false},
		{"email", false},
		{"id", false},
	}

	for _, c := range cases {
		if got := IsSensitiveKey(c.key); got != c.expected {
			t.Errorf("IsSensitiveKey(%q) = %v; want %v", c.key, got, c.expected)
		}
	}
}
