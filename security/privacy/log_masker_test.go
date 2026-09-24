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
