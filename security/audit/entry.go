package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"ztatic-go-framework/security/privacy"
)

// Severity indicates the security impact level of an audit event.
type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityWarn     Severity = "WARN"
	SeverityError    Severity = "ERROR"
	SeverityCritical Severity = "CRITICAL"
)

// Category groups audit events into standard compliance classifications.
type Category string

const (
	CategoryAuth     Category = "authentication"
	CategoryAccess   Category = "authorization"
	CategoryData     Category = "data_access"
	CategorySystem   Category = "system"
	CategorySecurity Category = "security"
)

// OutcomeStatus represents the final status of an audited transaction.
type OutcomeStatus string

const (
	OutcomeSuccess OutcomeStatus = "SUCCESS"
	OutcomeFailure OutcomeStatus = "FAILURE"
	OutcomeDenied  OutcomeStatus = "DENIED"
	OutcomeError   OutcomeStatus = "ERROR"
)

// Actor represents the entity or principal initiating an action.
type Actor struct {
	ID        string         `json:"id"`
	Type      string         `json:"type,omitempty"` // "user", "service_account", "system", "anonymous", "api_key"
	Name      string         `json:"name,omitempty"`
	Role      string         `json:"role,omitempty"`
	TenantID  string         `json:"tenant_id,omitempty"`
	IP        string         `json:"ip,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// Target represents the resource or entity being inspected or mutated.
type Target struct {
	Type       string         `json:"type,omitempty"` // e.g., "user", "billing_invoice", "role", "route"
	ID         string         `json:"id,omitempty"`
	Name       string         `json:"name,omitempty"`
	TenantID   string         `json:"tenant_id,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// Outcome records the result of the audited operation.
type Outcome struct {
	Status     OutcomeStatus `json:"status"`
	StatusCode int           `json:"status_code,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	DurationMs float64       `json:"duration_ms,omitempty"`
}

// Context records the execution and network environment details.
type Context struct {
	RequestID string `json:"request_id,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
	SpanID    string `json:"span_id,omitempty"`
	Method    string `json:"method,omitempty"`
	Path      string `json:"path,omitempty"`
	Route     string `json:"route,omitempty"`
	Host      string `json:"host,omitempty"`
}

// FieldChange captures a single field change between states.
type FieldChange struct {
	Field string `json:"field"`
	Old   any    `json:"old,omitempty"`
	New   any    `json:"new,omitempty"`
}

// Changes captures state transitions before and after mutations.
type Changes struct {
	Before map[string]any `json:"before,omitempty"`
	After  map[string]any `json:"after,omitempty"`
	Diff   []FieldChange  `json:"diff,omitempty"`
}

// Entry is the primary, immutable, structured audit log event record.
type Entry struct {
	ID        string         `json:"id"`
	Timestamp time.Time      `json:"timestamp"`
	Severity  Severity       `json:"severity"`
	Category  Category       `json:"category"`
	Action    string         `json:"action"` // e.g. "auth.login", "user.create", "order.refund"
	Actor     Actor          `json:"actor"`
	Target    Target         `json:"target,omitempty"`
	Outcome   Outcome        `json:"outcome"`
	Context   Context        `json:"context,omitempty"`
	Changes   Changes        `json:"changes,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// NewEntry initializes an audit entry with a unique ID and RFC3339 UTC timestamp.
func NewEntry(action string) *Entry {
	return &Entry{
		ID:        generateAuditID(),
		Timestamp: time.Now().UTC(),
		Severity:  SeverityInfo,
		Category:  CategoryData,
		Action:    action,
		Outcome: Outcome{
			Status: OutcomeSuccess,
		},
		Metadata: make(map[string]any),
	}
}

// generateAuditID creates a unique, cryptographically random audit ID with a timestamp prefix.
func generateAuditID() string {
	var randomBytes [8]byte
	_, _ = rand.Read(randomBytes[:])
	return fmt.Sprintf("aud_%x_%s", time.Now().UnixNano(), hex.EncodeToString(randomBytes[:]))
}

// WithActor sets basic actor details.
func (e *Entry) WithActor(id, actorType, name, role string) *Entry {
	e.Actor.ID = id
	e.Actor.Type = actorType
	e.Actor.Name = name
	e.Actor.Role = role
	return e
}

// WithActorStruct replaces the Actor with a full struct.
func (e *Entry) WithActorStruct(actor Actor) *Entry {
	e.Actor = actor
	return e
}

// WithTarget sets basic target details.
func (e *Entry) WithTarget(targetType, id, name string) *Entry {
	e.Target.Type = targetType
	e.Target.ID = id
	e.Target.Name = name
	return e
}

// WithTargetStruct replaces the Target with a full struct.
func (e *Entry) WithTargetStruct(target Target) *Entry {
	e.Target = target
	return e
}

// WithCategory sets the audit classification category.
func (e *Entry) WithCategory(cat Category) *Entry {
	e.Category = cat
	return e
}

// WithSeverity sets the severity level.
func (e *Entry) WithSeverity(sev Severity) *Entry {
	e.Severity = sev
	return e
}

// WithOutcome sets the outcome status, HTTP status code, and optional reason.
func (e *Entry) WithOutcome(status OutcomeStatus, statusCode int, reason string) *Entry {
	e.Outcome.Status = status
	e.Outcome.StatusCode = statusCode
	e.Outcome.Reason = reason

	// Align severity if it hasn't been explicitly upgraded
	if e.Severity == SeverityInfo {
		switch {
		case status == OutcomeDenied || statusCode == 401 || statusCode == 403:
			e.Severity = SeverityWarn
		case status == OutcomeError || statusCode >= 500:
			e.Severity = SeverityError
		case status == OutcomeFailure || (statusCode >= 400 && statusCode < 500):
			e.Severity = SeverityWarn
		}
	}
	return e
}

// WithDuration records the operation duration in milliseconds.
func (e *Entry) WithDuration(d time.Duration) *Entry {
	e.Outcome.DurationMs = float64(d.Microseconds()) / 1000.0
	return e
}

// WithContext sets network and HTTP context information.
func (e *Entry) WithContext(reqID, method, path, route, ip, userAgent string) *Entry {
	e.Context.RequestID = reqID
	e.Context.Method = method
	e.Context.Path = path
	e.Context.Route = route
	e.Actor.IP = ip
	e.Actor.UserAgent = userAgent
	return e
}

// WithTrace sets distributed trace and span IDs on the audit context.
func (e *Entry) WithTrace(traceID, spanID string) *Entry {
	e.Context.TraceID = traceID
	e.Context.SpanID = spanID
	return e
}

// WithDiff records state changes before and after an operation.
func (e *Entry) WithDiff(before, after map[string]any) *Entry {
	e.Changes.Before = before
	e.Changes.After = after

	// Compute field-level diff automatically
	var diffs []FieldChange
	allKeys := make(map[string]struct{})
	for k := range before {
		allKeys[k] = struct{}{}
	}
	for k := range after {
		allKeys[k] = struct{}{}
	}
	for k := range allKeys {
		oldVal := before[k]
		newVal := after[k]
		if fmt.Sprintf("%v", oldVal) != fmt.Sprintf("%v", newVal) {
			diffs = append(diffs, FieldChange{
				Field: k,
				Old:   oldVal,
				New:   newVal,
			})
		}
	}
	e.Changes.Diff = diffs
	return e
}

// WithMetadata adds a key-value attribute to the entry's metadata map.
func (e *Entry) WithMetadata(key string, val any) *Entry {
	if e.Metadata == nil {
		e.Metadata = make(map[string]any)
	}
	e.Metadata[key] = val
	return e
}

// Clone creates a shallow-to-medium clone of the audit entry.
func (e *Entry) Clone() *Entry {
	clone := *e
	if e.Metadata != nil {
		clone.Metadata = make(map[string]any, len(e.Metadata))
		for k, v := range e.Metadata {
			clone.Metadata[k] = v
		}
	}
	if e.Actor.Metadata != nil {
		clone.Actor.Metadata = make(map[string]any, len(e.Actor.Metadata))
		for k, v := range e.Actor.Metadata {
			clone.Actor.Metadata[k] = v
		}
	}
	if e.Target.Attributes != nil {
		clone.Target.Attributes = make(map[string]any, len(e.Target.Attributes))
		for k, v := range e.Target.Attributes {
			clone.Target.Attributes[k] = v
		}
	}
	if e.Changes.Before != nil {
		clone.Changes.Before = make(map[string]any, len(e.Changes.Before))
		for k, v := range e.Changes.Before {
			clone.Changes.Before[k] = v
		}
	}
	if e.Changes.After != nil {
		clone.Changes.After = make(map[string]any, len(e.Changes.After))
		for k, v := range e.Changes.After {
			clone.Changes.After[k] = v
		}
	}
	return &clone
}

// Sanitize returns a deep copy with all sensitive PII and credential keys redacted.
func (e *Entry) Sanitize() *Entry {
	cleaned := e.Clone()
	cleaned.Metadata = privacy.SanitizeMap(cleaned.Metadata)
	cleaned.Actor.Metadata = privacy.SanitizeMap(cleaned.Actor.Metadata)
	cleaned.Target.Attributes = privacy.SanitizeMap(cleaned.Target.Attributes)
	cleaned.Changes.Before = privacy.SanitizeMap(cleaned.Changes.Before)
	cleaned.Changes.After = privacy.SanitizeMap(cleaned.Changes.After)

	if len(cleaned.Changes.Diff) > 0 {
		sanitizedDiff := make([]FieldChange, len(cleaned.Changes.Diff))
		for i, d := range cleaned.Changes.Diff {
			if privacy.IsSensitiveKey(d.Field) {
				sanitizedDiff[i] = FieldChange{
					Field: d.Field,
					Old:   privacy.RedactedString,
					New:   privacy.RedactedString,
				}
			} else {
				sanitizedDiff[i] = d
			}
		}
		cleaned.Changes.Diff = sanitizedDiff
	}

	return cleaned
}

// JSON serializes the sanitized entry into JSON bytes.
func (e *Entry) JSON() ([]byte, error) {
	return json.Marshal(e.Sanitize())
}
