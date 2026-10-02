package ztatic_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	ztatic "ztatic-go-framework"
	"ztatic-go-framework/log"
	"ztatic-go-framework/security/audit"
	"ztatic-go-framework/trace"
)

func TestTrace_EndToEnd_NewSecure(t *testing.T) {
	var logBuf bytes.Buffer
	auditSink := audit.NewMemorySink(100)

	cfg := ztatic.DefaultConfig()
	cfg.Log.Output = &logBuf
	cfg.Log.Format = log.FormatJSON
	cfg.Security.EnableAudit = true
	cfg.Security.Audit = audit.AuditConfig{
		Logger: audit.NewSyncLogger(audit.NewJSONFormatter(false), auditSink, false),
	}

	app := ztatic.NewWithConfig(cfg)

	// Route 1: Successful response with response envelope
	app.GET("/api/items", func(c *ztatic.Context) error {
		tc := ztatic.TraceFromContext(c)
		reqID := ztatic.RequestIDFromContext(c)
		traceID := ztatic.TraceIDFromContext(c)
		spanID := ztatic.SpanIDFromContext(c)

		if tc.RequestID == "" || tc.RequestID != reqID {
			t.Errorf("expected matching RequestID, got tc: %s, helper: %s", tc.RequestID, reqID)
		}
		if tc.TraceID == "" || tc.TraceID != traceID {
			t.Errorf("expected matching TraceID, got tc: %s, helper: %s", tc.TraceID, traceID)
		}
		if tc.SpanID == "" || tc.SpanID != spanID {
			t.Errorf("expected matching SpanID, got tc: %s, helper: %s", tc.SpanID, spanID)
		}

		logger := ztatic.LogFromContext(c)
		logger.Info("fetching items in handler", "item_count", 2)

		return ztatic.OK(c, []string{"alpha", "beta"})
	})

	// Route 2: Error route returning standardized domain error
	app.GET("/api/fail", func(c *ztatic.Context) error {
		return ztatic.ErrNotFound("resource not found")
	})

	// Test Route 1: Success with incoming W3C traceparent
	incomingReqID := "client-req-8888"
	incomingTraceID := "4bf92f3577b34da6a3ce929d0e0e4736"
	incomingParentSpan := "00f067aa0ba902b7"
	incomingTP := "00-" + incomingTraceID + "-" + incomingParentSpan + "-01"

	req := httptest.NewRequest(http.MethodGet, "/api/items", nil)
	req.Header.Set(trace.HeaderXRequestID, incomingReqID)
	req.Header.Set(trace.HeaderTraceparent, incomingTP)
	rec := httptest.NewRecorder()

	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	// 1. Verify response headers
	resReqID := rec.Header().Get(trace.HeaderXRequestID)
	if resReqID != incomingReqID {
		t.Errorf("expected response X-Request-ID %s, got %s", incomingReqID, resReqID)
	}

	resTP := rec.Header().Get(trace.HeaderTraceparent)
	if resTP == "" {
		t.Fatalf("expected response traceparent header to be present")
	}
	parsedTraceID, localSpanID, sampled, err := trace.ParseTraceparent(resTP)
	if err != nil {
		t.Fatalf("failed to parse response traceparent: %v", err)
	}
	if parsedTraceID != incomingTraceID {
		t.Errorf("expected trace ID %s, got %s", incomingTraceID, parsedTraceID)
	}
	if localSpanID == incomingParentSpan {
		t.Errorf("expected local span ID to differ from incoming parent span ID")
	}
	if !sampled {
		t.Errorf("expected sampled true")
	}

	// 2. Verify response envelope JSON
	var parsedEnvelope struct {
		Success bool     `json:"success"`
		Data    []string `json:"data"`
		Meta    struct {
			RequestID string `json:"request_id"`
			TraceID   string `json:"trace_id"`
			Timestamp string `json:"timestamp"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &parsedEnvelope); err != nil {
		t.Fatalf("failed to parse envelope JSON: %v", err)
	}

	if !parsedEnvelope.Success {
		t.Errorf("expected success true in envelope")
	}
	if parsedEnvelope.Meta.RequestID != incomingReqID {
		t.Errorf("expected meta.request_id %s, got %s", incomingReqID, parsedEnvelope.Meta.RequestID)
	}
	if parsedEnvelope.Meta.TraceID != incomingTraceID {
		t.Errorf("expected meta.trace_id %s, got %s", incomingTraceID, parsedEnvelope.Meta.TraceID)
	}

	// 3. Verify structured log output contains req_id, trace_id, and span_id
	logStr := logBuf.String()
	if !strings.Contains(logStr, incomingReqID) {
		t.Errorf("expected log output to contain req_id %s, got: %s", incomingReqID, logStr)
	}
	if !strings.Contains(logStr, incomingTraceID) {
		t.Errorf("expected log output to contain trace_id %s, got: %s", incomingTraceID, logStr)
	}
	if !strings.Contains(logStr, localSpanID) {
		t.Errorf("expected log output to contain span_id %s, got: %s", localSpanID, logStr)
	}

	// Test Route 2: Standardized error correlation
	reqErr := httptest.NewRequest(http.MethodGet, "/api/fail", nil)
	recErr := httptest.NewRecorder()
	app.ServeHTTP(recErr, reqErr)

	if recErr.Code != http.StatusNotFound {
		t.Fatalf("expected HTTP 404, got %d", recErr.Code)
	}

	errReqID := recErr.Header().Get(trace.HeaderXRequestID)
	if errReqID == "" {
		t.Errorf("expected error response to have X-Request-ID header")
	}
	errTP := recErr.Header().Get(trace.HeaderTraceparent)
	if errTP == "" {
		t.Errorf("expected error response to have traceparent header")
	}

	var parsedErrResp struct {
		Success bool `json:"success"`
		Error   struct {
			Code      string `json:"code"`
			Message   string `json:"message"`
			RequestID string `json:"request_id"`
			TraceID   string `json:"trace_id"`
		} `json:"error"`
		Meta struct {
			RequestID string `json:"request_id"`
			TraceID   string `json:"trace_id"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(recErr.Body.Bytes(), &parsedErrResp); err != nil {
		t.Fatalf("failed to parse error response JSON: %v", err)
	}
	if parsedErrResp.Error.RequestID != errReqID {
		t.Errorf("expected error.request_id %s, got %s", errReqID, parsedErrResp.Error.RequestID)
	}
	if parsedErrResp.Error.TraceID == "" {
		t.Errorf("expected error.trace_id to be populated")
	}
	if parsedErrResp.Meta.TraceID != parsedErrResp.Error.TraceID {
		t.Errorf("expected meta.trace_id to match error.trace_id")
	}

	// 4. Verify Audit Ledger capture
	entries := auditSink.Entries()
	if len(entries) == 0 {
		t.Fatalf("expected audit entries to be recorded")
	}
	lastAudit := entries[len(entries)-1]
	if lastAudit.Context.RequestID != errReqID {
		t.Errorf("expected audit entry RequestID %s, got %s", errReqID, lastAudit.Context.RequestID)
	}
	if lastAudit.Context.TraceID == "" {
		t.Errorf("expected audit entry TraceID to be populated")
	}
	if lastAudit.Context.SpanID == "" {
		t.Errorf("expected audit entry SpanID to be populated")
	}
}

func TestTrace_LeanEngine_New(t *testing.T) {
	app := ztatic.New()

	app.GET("/ping", func(c *ztatic.Context) error {
		reqID := ztatic.RequestIDFromContext(c)
		traceID := ztatic.TraceIDFromContext(c)
		spanID := ztatic.SpanIDFromContext(c)

		if reqID == "" || traceID == "" || spanID == "" {
			t.Errorf("expected non-empty trace identifiers in lean engine")
		}
		return ztatic.OK(c, map[string]string{"status": "pong"})
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	if rec.Header().Get(trace.HeaderXRequestID) == "" {
		t.Errorf("expected X-Request-ID on lean engine response")
	}
	if rec.Header().Get(trace.HeaderTraceparent) == "" {
		t.Errorf("expected traceparent on lean engine response")
	}
}

func TestTrace_OutboundPropagation(t *testing.T) {
	// 1. Mock external microservice receiver
	var capturedOutboundReqID, capturedOutboundTP string
	mockDownstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedOutboundReqID = r.Header.Get(trace.HeaderXRequestID)
		capturedOutboundTP = r.Header.Get(trace.HeaderTraceparent)
		w.WriteHeader(http.StatusOK)
	}))
	defer mockDownstream.Close()

	// 2. Gateway app
	app := ztatic.NewSecure()
	tracingClient := trace.NewClient(mockDownstream.Client())

	app.GET("/proxy-call", func(c *ztatic.Context) error {
		// Outbound call using context from request
		ctx := c.Request().Context()
		outReq, err := http.NewRequestWithContext(ctx, http.MethodGet, mockDownstream.URL+"/downstream", nil)
		if err != nil {
			return err
		}

		resp, err := tracingClient.Do(outReq)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		return ztatic.OK(c, "proxied")
	})

	parentTraceID := "e4577ced349b426486111a1334c9c7d4"
	incomingTP := "00-" + parentTraceID + "-1122334455667788-01"

	req := httptest.NewRequest(http.MethodGet, "/proxy-call", nil)
	req.Header.Set(trace.HeaderXRequestID, "gateway-req-123")
	req.Header.Set(trace.HeaderTraceparent, incomingTP)

	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	// Verify downstream microservice received the propagated context
	if capturedOutboundReqID != "gateway-req-123" {
		t.Errorf("expected downstream to receive RequestID gateway-req-123, got %s", capturedOutboundReqID)
	}

	outTraceID, outSpanID, _, err := trace.ParseTraceparent(capturedOutboundTP)
	if err != nil {
		t.Fatalf("failed to parse downstream traceparent %s: %v", capturedOutboundTP, err)
	}
	if outTraceID != parentTraceID {
		t.Errorf("expected trace ID %s to be propagated downstream, got %s", parentTraceID, outTraceID)
	}
	if outSpanID == "1122334455667788" || outSpanID == "" {
		t.Errorf("expected downstream call to have a new outbound child span ID, got %s", outSpanID)
	}
}

