package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ztatic-go-framework/security/privacy"
)

func sampleEntry() *Entry {
	return NewEntry("user.role.update").
		WithActor("usr_admin", "user", "Super Admin", "admin").
		WithTarget("user", "usr_target_42", "John Doe").
		WithCategory(CategoryAccess).
		WithSeverity(SeverityWarn).
		WithOutcome(OutcomeSuccess, 200, "Role updated").
		WithDuration(12 * time.Millisecond).
		WithContext("req_123", "PUT", "/api/users/42/role", "/api/users/:id/role", "10.0.0.1", "curl/8.0").
		WithMetadata("password", "leaked-secret"). // should be sanitized
		WithMetadata("environment", "production")
}

func TestJSONFormatter(t *testing.T) {
	entry := sampleEntry()

	// 1. Compact / NDJSON
	compactFmt := NewJSONFormatter(false)
	compactBytes, err := compactFmt.Format(entry)
	if err != nil {
		t.Fatalf("compact format failed: %v", err)
	}
	if !strings.HasSuffix(string(compactBytes), "\n") {
		t.Errorf("expected NDJSON trailing newline")
	}
	if strings.Contains(string(compactBytes), "leaked-secret") {
		t.Errorf("secret leaked in JSON format")
	}
	if !strings.Contains(string(compactBytes), privacy.RedactedString) {
		t.Errorf("expected redacted string in output")
	}

	var parsed map[string]any
	if err := json.Unmarshal(compactBytes, &parsed); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}
	if parsed["action"] != "user.role.update" {
		t.Errorf("unexpected action: %v", parsed["action"])
	}

	// 2. Pretty
	prettyFmt := NewJSONFormatter(true)
	prettyBytes, err := prettyFmt.Format(entry)
	if err != nil {
		t.Fatalf("pretty format failed: %v", err)
	}
	if !strings.Contains(string(prettyBytes), "  \"action\": \"user.role.update\"") {
		t.Errorf("expected pretty indented JSON")
	}
}

func TestCloudEventsFormatter(t *testing.T) {
	entry := sampleEntry()
	fmt := NewCloudEventsFormatter("ztatic/system-test")

	if fmt.ContentType() != "application/cloudevents+json" {
		t.Errorf("expected application/cloudevents+json, got %s", fmt.ContentType())
	}

	bytes, err := fmt.Format(entry)
	if err != nil {
		t.Fatalf("cloudevents format failed: %v", err)
	}

	var ce CloudEventsRecord
	if err := json.Unmarshal(bytes, &ce); err != nil {
		t.Fatalf("failed to unmarshal CloudEvent: %v", err)
	}

	if ce.SpecVersion != "1.0" {
		t.Errorf("expected specversion 1.0, got %s", ce.SpecVersion)
	}
	if ce.Source != "ztatic/system-test" {
		t.Errorf("expected source ztatic/system-test, got %s", ce.Source)
	}
	if ce.Type != "org.ztatic.audit.user.role.update" {
		t.Errorf("expected event type org.ztatic.audit.user.role.update, got %s", ce.Type)
	}
	if ce.Data == nil || ce.Data.Action != "user.role.update" {
		t.Errorf("cloudevent data payload missing or corrupted")
	}
	if strings.Contains(string(bytes), "leaked-secret") {
		t.Errorf("secret leaked in CloudEvent payload")
	}
}

func TestCEFFormatter(t *testing.T) {
	entry := sampleEntry()
	cef := NewCEFFormatter("ZtaticOrg", "SecEngine", "2.0")

	bytes, err := cef.Format(entry)
	if err != nil {
		t.Fatalf("CEF format failed: %v", err)
	}

	cefLine := string(bytes)
	if !strings.HasPrefix(cefLine, "CEF:0|ZtaticOrg|SecEngine|2.0|user.role.update|authorization: user.role.update|4|") {
		t.Errorf("unexpected CEF header: %s", cefLine)
	}

	// Verify extensions
	if !strings.Contains(cefLine, "suser=usr_admin") {
		t.Errorf("missing suser in CEF: %s", cefLine)
	}
	if !strings.Contains(cefLine, "src=10.0.0.1") {
		t.Errorf("missing src in CEF: %s", cefLine)
	}
	if !strings.Contains(cefLine, "cs1=user") || !strings.Contains(cefLine, "cs2=usr_target_42") {
		t.Errorf("missing target in CEF: %s", cefLine)
	}
	if !strings.Contains(cefLine, "cn1=200") {
		t.Errorf("missing HTTP status in CEF: %s", cefLine)
	}
}

func TestTextFormatter(t *testing.T) {
	entry := sampleEntry()
	txtFmt := NewTextFormatter(false)

	bytes, err := txtFmt.Format(entry)
	if err != nil {
		t.Fatalf("text format failed: %v", err)
	}

	out := string(bytes)
	if !strings.Contains(out, "[AUDIT]") {
		t.Errorf("expected [AUDIT] prefix in: %s", out)
	}
	if !strings.Contains(out, "actor=usr_admin(admin)") {
		t.Errorf("expected actor info in: %s", out)
	}
	if !strings.Contains(out, "target=user:usr_target_42") {
		t.Errorf("expected target info in: %s", out)
	}
	if !strings.Contains(out, "[PUT /api/users/42/role -> 200 (12.0ms)]") {
		t.Errorf("expected HTTP summary in: %s", out)
	}

	// With colors
	colorFmt := NewTextFormatter(true)
	colorBytes, err := colorFmt.Format(entry)
	if err != nil {
		t.Fatalf("color text format failed: %v", err)
	}
	if !strings.Contains(string(colorBytes), "\033[") {
		t.Errorf("expected ANSI color codes in colorized output")
	}
}
