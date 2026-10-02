package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"ztatic-go-framework/security/privacy"
)

func TestNewEntry_Defaults(t *testing.T) {
	entry := NewEntry("user.login")

	if entry.ID == "" {
		t.Errorf("expected generated ID, got empty string")
	}
	if !strings.HasPrefix(entry.ID, "aud_") {
		t.Errorf("expected ID prefix 'aud_', got %s", entry.ID)
	}
	if entry.Action != "user.login" {
		t.Errorf("expected action 'user.login', got %s", entry.Action)
	}
	if entry.Severity != SeverityInfo {
		t.Errorf("expected severity INFO, got %s", entry.Severity)
	}
	if entry.Outcome.Status != OutcomeSuccess {
		t.Errorf("expected outcome SUCCESS, got %s", entry.Outcome.Status)
	}
	if entry.Timestamp.IsZero() {
		t.Errorf("expected valid UTC timestamp")
	}
}

func TestEntry_Builders(t *testing.T) {
	entry := NewEntry("billing.invoice.pay").
		WithActor("usr_99", "user", "Alice Smith", "finance_admin").
		WithTarget("invoice", "inv_1234", "March Subscription").
		WithCategory(CategoryData).
		WithSeverity(SeverityWarn).
		WithOutcome(OutcomeSuccess, 200, "Card processed").
		WithDuration(45 * time.Millisecond).
		WithContext("req_abc", "POST", "/api/invoices/inv_1234/pay", "/api/invoices/:id/pay", "192.168.1.50", "Mozilla/5.0").
		WithMetadata("gateway", "stripe").
		WithDiff(
			map[string]any{"status": "pending", "amount": 100},
			map[string]any{"status": "paid", "amount": 100},
		)

	if entry.Actor.ID != "usr_99" || entry.Actor.Role != "finance_admin" {
		t.Errorf("actor builder failed: %+v", entry.Actor)
	}
	if entry.Target.ID != "inv_1234" || entry.Target.Type != "invoice" {
		t.Errorf("target builder failed: %+v", entry.Target)
	}
	if entry.Outcome.StatusCode != 200 || entry.Outcome.DurationMs <= 0 {
		t.Errorf("outcome builder failed: %+v", entry.Outcome)
	}
	if entry.Context.RequestID != "req_abc" || entry.Context.Method != "POST" {
		t.Errorf("context builder failed: %+v", entry.Context)
	}
	if len(entry.Changes.Diff) != 1 || entry.Changes.Diff[0].Field != "status" {
		t.Errorf("diff calculation failed: %+v", entry.Changes.Diff)
	}
	if entry.Changes.Diff[0].Old != "pending" || entry.Changes.Diff[0].New != "paid" {
		t.Errorf("diff old/new mismatch: %+v", entry.Changes.Diff[0])
	}
}

func TestEntry_Sanitization_RedactsSensitiveData(t *testing.T) {
	entry := NewEntry("auth.register").
		WithActor("usr_1", "user", "Bob", "member").
		WithMetadata("api_key", "secret-key-12345").
		WithMetadata("public_info", "harmless").
		WithDiff(
			map[string]any{"password": "plain-text-pass", "email": "bob@example.com"},
			map[string]any{"password": "new-secret-pass", "email": "bob@example.com"},
		)

	entry.Actor.Metadata = map[string]any{
		"token": "bearer-secret-token",
		"tier":  "enterprise",
	}

	sanitized := entry.Sanitize()

	// Check metadata
	if sanitized.Metadata["api_key"] != privacy.RedactedString {
		t.Errorf("expected api_key redacted, got %v", sanitized.Metadata["api_key"])
	}
	if sanitized.Metadata["public_info"] != "harmless" {
		t.Errorf("expected harmless metadata untouched, got %v", sanitized.Metadata["public_info"])
	}

	// Check actor metadata
	if sanitized.Actor.Metadata["token"] != privacy.RedactedString {
		t.Errorf("expected token redacted in actor metadata, got %v", sanitized.Actor.Metadata["token"])
	}
	if sanitized.Actor.Metadata["tier"] != "enterprise" {
		t.Errorf("expected tier preserved, got %v", sanitized.Actor.Metadata["tier"])
	}

	// Check diffs
	if sanitized.Changes.Before["password"] != privacy.RedactedString {
		t.Errorf("expected password in Changes.Before redacted, got %v", sanitized.Changes.Before["password"])
	}
	if sanitized.Changes.After["password"] != privacy.RedactedString {
		t.Errorf("expected password in Changes.After redacted, got %v", sanitized.Changes.After["password"])
	}

	for _, d := range sanitized.Changes.Diff {
		if d.Field == "password" {
			if d.Old != privacy.RedactedString || d.New != privacy.RedactedString {
				t.Errorf("diff for password not redacted: %+v", d)
			}
		}
	}

	// Check JSON serialization
	jsonBytes, err := entry.JSON()
	if err != nil {
		t.Fatalf("JSON serialization failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(jsonBytes, &parsed); err != nil {
		t.Fatalf("JSON parse failed: %v", err)
	}

	rawJSON := string(jsonBytes)
	if strings.Contains(rawJSON, "plain-text-pass") || strings.Contains(rawJSON, "secret-key-12345") || strings.Contains(rawJSON, "bearer-secret-token") {
		t.Errorf("raw JSON contains leaked secrets: %s", rawJSON)
	}
}
