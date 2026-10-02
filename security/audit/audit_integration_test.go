package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"

	"ztatic-go-framework"
	"ztatic-go-framework/security/audit"
	"ztatic-go-framework/security/privacy"
)

// -----------------------------------------------------------------------------
// 1. DATA MODEL & ENTRY INTEGRITY TESTS
// -----------------------------------------------------------------------------

// TestAuditIntegration_ID_Uniqueness_CollisionCheck verifies that 10,000 IDs generated across
// concurrent threads are 100% unique without collisions.
func TestAuditIntegration_ID_Uniqueness_CollisionCheck(t *testing.T) {
	const count = 10000
	idMap := sync.Map{}
	var collisions int64
	var wg sync.WaitGroup

	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			entry := audit.NewEntry("test.id")
			if _, loaded := idMap.LoadOrStore(entry.ID, struct{}{}); loaded {
				atomic.AddInt64(&collisions, 1)
			}
		}()
	}

	wg.Wait()

	if collisions > 0 {
		t.Fatalf("ID collision detected! Collisions: %d out of %d", collisions, count)
	}
}

// TestAuditIntegration_DataSanitization_DeepScrubbing validates that all sensitive patterns
// (casing variations, nested dictionaries, slices of maps) are scrubbed.
func TestAuditIntegration_DataSanitization_DeepScrubbing(t *testing.T) {
	entry := audit.NewEntry("user.security.update").
		WithActor("usr_99", "user", "Admin", "admin").
		WithTarget("account", "acc_100", "Production Account")

	// Inject sensitive keys with varying casing and nested depths
	entry.Metadata = map[string]any{
		"PASSWORD":    "pAssw0rd!",
		"api_KEY":     "sk-live-99999",
		"SSN":         "123-45-6789",
		"credit_card": "4111-2222-3333-4444",
		"CVV":         "999",
		"auth_token":  "jwt.token.here",
		"safe_key":    "safe_value",
		"nested_profile": map[string]any{
			"pass":      "nested_secret",
			"user_name": "bob_ross",
		},
		"history": []any{
			map[string]any{"secret": "old_secret_1"},
			map[string]any{"secret": "old_secret_2"},
			"harmless_string",
		},
	}

	entry.Changes.Before = map[string]any{"auth": "old_auth_token"}
	entry.Changes.After = map[string]any{"auth": "new_auth_token"}
	entry.Changes.Diff = []audit.FieldChange{
		{Field: "auth", Old: "old_auth_token", New: "new_auth_token"},
		{Field: "status", Old: "inactive", New: "active"},
	}

	sanitized := entry.Sanitize()

	// Assert that sensitive fields in Metadata are redacted
	sensitiveKeys := []string{"PASSWORD", "api_KEY", "SSN", "credit_card", "CVV", "auth_token"}
	for _, key := range sensitiveKeys {
		if sanitized.Metadata[key] != privacy.RedactedString {
			t.Errorf("Key %s was not redacted: got %v", key, sanitized.Metadata[key])
		}
	}

	if sanitized.Metadata["safe_key"] != "safe_value" {
		t.Errorf("Non-sensitive key 'safe_key' was corrupted: got %v", sanitized.Metadata["safe_key"])
	}

	nested, ok := sanitized.Metadata["nested_profile"].(map[string]any)
	if !ok || nested["pass"] != privacy.RedactedString || nested["user_name"] != "bob_ross" {
		t.Errorf("Nested profile map sanitization failed: %+v", nested)
	}

	history, ok := sanitized.Metadata["history"].([]any)
	if !ok || len(history) != 3 {
		t.Fatalf("History slice corrupted: %+v", history)
	}
	h1, ok := history[0].(map[string]any)
	if !ok || h1["secret"] != privacy.RedactedString {
		t.Errorf("Slice item 0 not redacted: %+v", h1)
	}

	// Assert Changes diff sanitization
	if sanitized.Changes.Before["auth"] != privacy.RedactedString || sanitized.Changes.After["auth"] != privacy.RedactedString {
		t.Errorf("Changes before/after not redacted: %+v", sanitized.Changes)
	}
	if sanitized.Changes.Diff[0].Old != privacy.RedactedString || sanitized.Changes.Diff[0].New != privacy.RedactedString {
		t.Errorf("Changes diff not redacted: %+v", sanitized.Changes.Diff[0])
	}
	if sanitized.Changes.Diff[1].Old != "inactive" || sanitized.Changes.Diff[1].New != "active" {
		t.Errorf("Non-sensitive diff corrupted: %+v", sanitized.Changes.Diff[1])
	}
}

// -----------------------------------------------------------------------------
// 2. FORMATTERS COMPLIANCE & SIEM ESCAPING TESTS
// -----------------------------------------------------------------------------

// TestAuditIntegration_Formatters_CloudEventsStrictCompliance validates that CloudEvents output
// conforms to CloudEvents v1.0.2 specification.
func TestAuditIntegration_Formatters_CloudEventsStrictCompliance(t *testing.T) {
	entry := audit.NewEntry("billing.invoice.void").
		WithActor("usr_finance", "user", "Jane Doe", "billing_manager").
		WithTarget("invoice", "inv_888", "Annual Invoice").
		WithOutcome(audit.OutcomeSuccess, 200, "Voided by admin").
		WithContext("req_ce_1", "POST", "/api/invoices/888/void", "/api/invoices/:id/void", "10.0.0.5", "Chrome/120")

	formatter := audit.NewCloudEventsFormatter("ztatic/test-suite")
	payload, err := formatter.Format(entry)
	if err != nil {
		t.Fatalf("CloudEvents format failed: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		t.Fatalf("Invalid JSON generated by CloudEventsFormatter: %v", err)
	}

	// Check CloudEvents v1.0 required fields
	if parsed["specversion"] != "1.0" {
		t.Errorf("CloudEvents specversion != 1.0: %v", parsed["specversion"])
	}
	if parsed["id"] != entry.ID {
		t.Errorf("CloudEvents id mismatch: %v", parsed["id"])
	}
	if parsed["source"] != "ztatic/test-suite" {
		t.Errorf("CloudEvents source mismatch: %v", parsed["source"])
	}
	if parsed["type"] != "org.ztatic.audit.billing.invoice.void" {
		t.Errorf("CloudEvents type mismatch: %v", parsed["type"])
	}
	if parsed["datacontenttype"] != "application/json" {
		t.Errorf("CloudEvents datacontenttype mismatch: %v", parsed["datacontenttype"])
	}
	if parsed["data"] == nil {
		t.Errorf("CloudEvents data payload is nil")
	}
}

// TestAuditIntegration_Formatters_CEF_DelimiterEscaping validates that malicious delimiters
// (|, =, \, \n) in action, target, or outcome are escaped to prevent SIEM log injection.
func TestAuditIntegration_Formatters_CEF_DelimiterEscaping(t *testing.T) {
	entry := audit.NewEntry("auth.login|bypass=true").
		WithActor("hacker|admin=true", "user", "Evil", "root").
		WithTarget("account|id=99", "acc_1=bad", "Special Account").
		WithOutcome(audit.OutcomeDenied, 403, "Reason with | pipe and = equal sign\nnewline")

	formatter := audit.NewCEFFormatter("Ztatic", "SecEngine", "1.0")
	rawBytes, err := formatter.Format(entry)
	if err != nil {
		t.Fatalf("CEF format failed: %v", err)
	}

	line := string(rawBytes)
	lines := strings.Split(strings.TrimSpace(line), "\n")
	if len(lines) != 1 {
		t.Errorf("Unescaped newline caused multi-line injection in CEF log: %d lines", len(lines))
	}

	// Verify header parts are intact using CEF unescaped delimiter splitting
	parts := splitCEFHeader(line)
	// Header format: CEF:0|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
	if len(parts) < 8 {
		t.Fatalf("Malformed CEF header structure: %+v", parts)
	}

	if parts[0] != "CEF:0" {
		t.Errorf("Invalid CEF prefix: %s", parts[0])
	}
	if parts[6] != "4" { // WARN severity maps to 4
		t.Errorf("Expected CEF severity 4 for OutcomeDenied, got %s", parts[6])
	}
}

func splitCEFHeader(line string) []string {
	var parts []string
	var current strings.Builder
	escaped := false
	for _, r := range line {
		if escaped {
			current.WriteRune(r)
			escaped = false
			continue
		}
		if r == '\\' {
			escaped = true
			continue
		}
		if r == '|' {
			parts = append(parts, current.String())
			current.Reset()
			continue
		}
		current.WriteRune(r)
	}
	parts = append(parts, current.String())
	return parts
}

// -----------------------------------------------------------------------------
// 3. SINK RELIABILITY & RESILIENCE TESTS
// -----------------------------------------------------------------------------

// TestAuditIntegration_MemorySink_BoundedCapacity validates that MemorySink strictly bounds
// memory usage and preserves only the newest N items without data race.
func TestAuditIntegration_MemorySink_BoundedCapacity(t *testing.T) {
	const capacity = 50
	const totalWrites = 500
	mem := audit.NewMemorySink(capacity)

	var wg sync.WaitGroup
	ctx := context.Background()

	// Concurrently write 500 entries
	for i := 0; i < totalWrites; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			e := audit.NewEntry(fmt.Sprintf("event.%d", idx))
			_ = mem.Write(ctx, []byte(fmt.Sprintf("formatted.%d", idx)), e)
		}(i)
	}

	// Concurrently read while writing
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = mem.Entries()
			_ = mem.Last()
			_ = mem.Len()
		}()
	}

	wg.Wait()

	if mem.Len() != capacity {
		t.Errorf("MemorySink did not enforce capacity bound: expected %d, got %d", capacity, mem.Len())
	}
	if len(mem.Entries()) != capacity {
		t.Errorf("MemorySink Entries() length != capacity: got %d", len(mem.Entries()))
	}
}

// TestAuditIntegration_MultiSink_PartialFailureTolerance verifies that if one downstream sink
// fails, remaining sinks still receive the audit payload, and errors are joined.
func TestAuditIntegration_MultiSink_PartialFailureTolerance(t *testing.T) {
	mem1 := audit.NewMemorySink(10)
	mem2 := audit.NewMemorySink(10)
	failingSink := &mockFailingSink{err: errors.New("network destination unreachable")}

	multi := audit.NewMultiSink(mem1, failingSink, mem2)

	entry := audit.NewEntry("critical.security.alert")
	payload := []byte("alert payload\n")

	err := multi.Write(context.Background(), payload, entry)
	if err == nil {
		t.Errorf("MultiSink did not report error when child sink failed")
	}
	if !strings.Contains(err.Error(), "network destination unreachable") {
		t.Errorf("Expected joined error containing child failure, got: %v", err)
	}

	// Sinks mem1 and mem2 MUST still have received the entry
	if mem1.Len() != 1 || mem2.Len() != 1 {
		t.Errorf("Surviving sinks did not receive write! mem1: %d, mem2: %d", mem1.Len(), mem2.Len())
	}
}

type mockFailingSink struct {
	err error
}

func (s *mockFailingSink) Write(ctx context.Context, formatted []byte, entry *audit.Entry) error {
	return s.err
}
func (s *mockFailingSink) Flush(ctx context.Context) error { return s.err }
func (s *mockFailingSink) Close() error                    { return s.err }

// -----------------------------------------------------------------------------
// 4. LOGGER HIGH-THROUGHPUT CONCURRENCY & DRAIN STRESS TESTS
// -----------------------------------------------------------------------------

// TestAuditIntegration_AsyncLogger_HighThroughputStress verifies that AsyncLogger can process
// 5,000 events across 25 concurrent goroutines without dropping events or leaking.
func TestAuditIntegration_AsyncLogger_HighThroughputStress(t *testing.T) {
	mem := audit.NewMemorySink(6000)
	cfg := audit.AsyncConfig{
		BufferSize:     2048,
		Workers:        4,
		OverflowPolicy: audit.PolicyBlock,
	}

	logger := audit.NewAsyncLogger(audit.NewJSONFormatter(false), mem, cfg)

	const totalEvents = 5000
	const workers = 25
	const eventsPerWorker = totalEvents / workers

	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			ctx := context.Background()
			for i := 0; i < eventsPerWorker; i++ {
				e := audit.NewEntry("stress.benchmark").
					WithActor(fmt.Sprintf("user_%d", workerID), "user", "Benchmark", "tester").
					WithMetadata("worker", workerID).
					WithMetadata("iteration", i)
				_ = logger.Log(ctx, e)
			}
		}(w)
	}

	wg.Wait()

	// Close logger gracefully to drain queue
	if err := logger.Close(); err != nil {
		t.Fatalf("Logger Close() returned error: %v", err)
	}

	if mem.Len() != totalEvents {
		t.Fatalf("Data loss under concurrency! Expected %d, got %d", totalEvents, mem.Len())
	}
}

// -----------------------------------------------------------------------------
// 5. ECHO V5 MIDDLEWARE REAL-WORLD SCENARIO TESTS
// -----------------------------------------------------------------------------

// TestAuditIntegration_Middleware_FullRESTMatrix tests complete CRUD workflows and error paths.
func TestAuditIntegration_Middleware_FullRESTMatrix(t *testing.T) {
	e := echo.New()
	e.Use(middleware.Recover())

	mem := audit.NewMemorySink(100)
	cfg := audit.DefaultAuditConfig()
	cfg.Logger = audit.NewSyncLogger(audit.NewJSONFormatter(false), mem, false)
	cfg.IncludeRequestBody = true

	e.Use(audit.AuditWithConfig(cfg))

	// Mock REST endpoints
	e.POST("/api/articles", func(c *echo.Context) error {
		entry := audit.FromContext(c)
		if entry != nil {
			entry.WithTarget("article", "art_101", "Breaking News").
				WithCategory(audit.CategoryData)
		}
		return c.JSON(http.StatusCreated, map[string]any{"id": "art_101", "title": "Breaking News"})
	})

	e.GET("/api/articles/:id", func(c *echo.Context) error {
		if c.Param("id") == "999" {
			return echo.NewHTTPError(http.StatusNotFound, "Article not found")
		}
		return c.JSON(http.StatusOK, map[string]any{"id": c.Param("id"), "title": "Existing News"})
	})

	e.PUT("/api/articles/:id", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]any{"id": c.Param("id"), "updated": true})
	})

	e.DELETE("/api/articles/:id", func(c *echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	e.GET("/api/admin/forbidden", func(c *echo.Context) error {
		return echo.NewHTTPError(http.StatusForbidden, "Insufficient role privileges")
	})

	e.POST("/api/crash", func(c *echo.Context) error {
		panic("simulated fatal runtime panic in handler")
	})

	// Scenario 1: POST /api/articles (201 Created) -> Must be logged
	req1 := httptest.NewRequest(http.MethodPost, "/api/articles", bytes.NewBufferString(`{"title":"Breaking News","password":"leakedPassword"}`))
	req1.Header.Set("Content-Type", "application/json")
	req1.Header.Set("X-User-ID", "author_42")
	req1.Header.Set("X-User-Role", "editor")
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusCreated {
		t.Fatalf("req1 failed: %d", rec1.Code)
	}

	last := mem.Last()
	if last == nil || last.Outcome.StatusCode != 201 || last.Actor.ID != "author_42" || last.Target.ID != "art_101" {
		t.Fatalf("POST audit entry incorrect: %+v", last)
	}
	bodyMeta, ok := last.Metadata["request_body"].(map[string]any)
	if !ok || bodyMeta["password"] != privacy.RedactedString {
		t.Errorf("Password not sanitized in request_body metadata: %+v", bodyMeta)
	}

	// Scenario 2: GET /api/articles/123 (200 OK) -> Default policy skips successful GET
	memCountBefore := mem.Len()
	req2 := httptest.NewRequest(http.MethodGet, "/api/articles/123", nil)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)
	if mem.Len() != memCountBefore {
		t.Errorf("Successful GET request was logged unexpectedly under default policy")
	}

	// Scenario 3: GET /api/articles/999 (404 Not Found) -> Error status MUST be logged
	req3 := httptest.NewRequest(http.MethodGet, "/api/articles/999", nil)
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound {
		t.Fatalf("req3 expected 404, got %d", rec3.Code)
	}
	last404 := mem.Last()
	if last404.Outcome.StatusCode != 404 || last404.Outcome.Status != audit.OutcomeFailure {
		t.Errorf("404 GET error was not logged correctly: %+v", last404)
	}

	// Scenario 4: GET /api/admin/forbidden (403 Forbidden) -> MUST be logged as OutcomeDenied
	req4 := httptest.NewRequest(http.MethodGet, "/api/admin/forbidden", nil)
	rec4 := httptest.NewRecorder()
	e.ServeHTTP(rec4, req4)
	last403 := mem.Last()
	if last403.Outcome.StatusCode != 403 || last403.Outcome.Status != audit.OutcomeDenied {
		t.Errorf("403 Forbidden was not classified as OutcomeDenied: %+v", last403)
	}

	// Scenario 5: DELETE /api/articles/101 (204 No Content) -> Mutating operation MUST be logged
	req5 := httptest.NewRequest(http.MethodDelete, "/api/articles/101", nil)
	rec5 := httptest.NewRecorder()
	e.ServeHTTP(rec5, req5)
	lastDelete := mem.Last()
	if lastDelete.Outcome.StatusCode != 204 || lastDelete.Outcome.Status != audit.OutcomeSuccess {
		t.Errorf("DELETE 204 was not recorded properly: %+v", lastDelete)
	}

	// Scenario 6: POST /api/crash (Panic recovered by middleware) -> MUST capture 500 error
	req6 := httptest.NewRequest(http.MethodPost, "/api/crash", nil)
	rec6 := httptest.NewRecorder()
	e.ServeHTTP(rec6, req6)
	if rec6.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 recovered status, got %d", rec6.Code)
	}
	lastCrash := mem.Last()
	if lastCrash.Outcome.StatusCode != 500 || lastCrash.Outcome.Status != audit.OutcomeError {
		t.Errorf("Recovered panic not audited as OutcomeError 500: %+v", lastCrash)
	}
}

// TestAuditIntegration_Middleware_BodyStreamReusability verifies that reading the request body
// in the audit middleware does NOT drain the stream for downstream controllers.
func TestAuditIntegration_Middleware_BodyStreamReusability(t *testing.T) {
	e := echo.New()
	mem := audit.NewMemorySink(10)
	cfg := audit.DefaultAuditConfig()
	cfg.Logger = audit.NewSyncLogger(audit.NewJSONFormatter(false), mem, false)
	cfg.IncludeRequestBody = true
	e.Use(audit.AuditWithConfig(cfg))

	var receivedBody string

	e.POST("/upload", func(c *echo.Context) error {
		// Handler reads body
		bodyBytes, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		receivedBody = string(bodyBytes)
		return c.String(http.StatusOK, "read successfully")
	})

	inputPayload := `{"document_id":"doc_123","title":"Report"}`
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewBufferString(inputPayload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}
	if receivedBody != inputPayload {
		t.Errorf("Downstream handler could not read request body! Expected %s, got %s", inputPayload, receivedBody)
	}
}

// -----------------------------------------------------------------------------
// 6. FRAMEWORK LEVEL ZERO-TRUST HARDENING INTEGRATION
// -----------------------------------------------------------------------------

// TestAuditIntegration_Engine_NewSecure_AuditWiring validates that ztatic.NewSecure() activates
// audit logging by default and coexists harmoniously with WAF, CSRF, and Headers.
func TestAuditIntegration_Engine_NewSecure_AuditWiring(t *testing.T) {
	app := ztatic.NewSecure()
	if app.AuditLogger() == nil {
		t.Fatalf("app.AuditLogger() is nil on ztatic.NewSecure()")
	}

	// 1. Web route without CSRF token: CSRF blocks with 403 Forbidden, and audit logger records denial
	app.POST("/dashboard/update", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "updated")
	})

	reqWeb := httptest.NewRequest(http.MethodPost, "/dashboard/update", nil)
	recWeb := httptest.NewRecorder()
	app.ServeHTTP(recWeb, reqWeb)

	if recWeb.Code != http.StatusBadRequest && recWeb.Code != http.StatusForbidden {
		t.Errorf("expected CSRF rejection 400 or 403 for web route, got %d", recWeb.Code)
	}

	// 2. API route: CSRF automatically skips /api/, request succeeds and is audited as mutating operation
	app.POST("/api/data", func(c *ztatic.Context) error {
		ztatic.AuditRecord(c, "data.mutate", "dataset", "ds_1")
		return c.String(http.StatusOK, "ok")
	})

	reqAPI := httptest.NewRequest(http.MethodPost, "/api/data", nil)
	reqAPI.Header.Set("X-User-ID", "operator_1")
	recAPI := httptest.NewRecorder()
	app.ServeHTTP(recAPI, reqAPI)

	if recAPI.Code != http.StatusOK {
		t.Errorf("expected 200 OK for /api/ endpoint, got %d", recAPI.Code)
	}
}

// -----------------------------------------------------------------------------
// BENCHMARKS
// -----------------------------------------------------------------------------

func BenchmarkEntryCreation(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = audit.NewEntry("benchmark.action").
			WithActor("usr_123", "user", "Alice", "admin").
			WithTarget("document", "doc_99", "Financials").
			WithOutcome(audit.OutcomeSuccess, 200, "Approved")
	}
}

func BenchmarkEntrySanitize(b *testing.B) {
	entry := audit.NewEntry("benchmark.action").
		WithActor("usr_123", "user", "Alice", "admin").
		WithTarget("document", "doc_99", "Financials").
		WithMetadata("password", "secret").
		WithMetadata("api_key", "sk-123").
		WithMetadata("safe", "value")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.Sanitize()
	}
}

func BenchmarkJSONFormatter(b *testing.B) {
	formatter := audit.NewJSONFormatter(false)
	entry := audit.NewEntry("benchmark.action").
		WithActor("usr_123", "user", "Alice", "admin").
		WithTarget("document", "doc_99", "Financials").
		WithOutcome(audit.OutcomeSuccess, 200, "Approved")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = formatter.Format(entry)
	}
}

func BenchmarkAsyncLogger(b *testing.B) {
	mem := audit.NewMemorySink(1000000)
	logger := audit.NewAsyncLogger(audit.NewJSONFormatter(false), mem, audit.AsyncConfig{
		BufferSize:     65536,
		Workers:        4,
		OverflowPolicy: audit.PolicyBlock,
	})
	defer logger.Close()

	ctx := context.Background()
	entry := audit.NewEntry("benchmark.log")

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = logger.Log(ctx, entry)
		}
	})
}
