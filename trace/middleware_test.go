package trace

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestMiddleware_DefaultGeneration(t *testing.T) {
	e := echo.New()
	e.Use(Middleware())

	var capturedTC TraceContext
	var capturedEchoReqID, capturedEchoTraceID, capturedEchoSpanID any

	e.GET("/test", func(c *echo.Context) error {
		capturedTC = FromContext(c.Request().Context())
		capturedEchoReqID = c.Get("request_id")
		capturedEchoTraceID = c.Get("trace_id")
		capturedEchoSpanID = c.Get("span_id")
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d", rec.Code)
	}

	resReqID := rec.Header().Get(HeaderXRequestID)
	if resReqID == "" {
		t.Fatalf("expected response header X-Request-ID to be set")
	}

	resTraceparent := rec.Header().Get(HeaderTraceparent)
	if resTraceparent == "" {
		t.Fatalf("expected response header traceparent to be set")
	}

	traceID, spanID, sampled, err := ParseTraceparent(resTraceparent)
	if err != nil {
		t.Fatalf("failed to parse returned traceparent header: %v", err)
	}

	if !sampled {
		t.Errorf("expected sampled to be true")
	}

	// Verify context capture
	if capturedTC.RequestID != resReqID {
		t.Errorf("expected captured RequestID %s, got %s", resReqID, capturedTC.RequestID)
	}
	if capturedTC.TraceID != traceID {
		t.Errorf("expected captured TraceID %s, got %s", traceID, capturedTC.TraceID)
	}
	if capturedTC.SpanID != spanID {
		t.Errorf("expected captured SpanID %s, got %s", spanID, capturedTC.SpanID)
	}

	// Verify Echo context bindings
	if capturedEchoReqID != resReqID {
		t.Errorf("expected echo context request_id %v, got %v", resReqID, capturedEchoReqID)
	}
	if capturedEchoTraceID != traceID {
		t.Errorf("expected echo context trace_id %v, got %v", traceID, capturedEchoTraceID)
	}
	if capturedEchoSpanID != spanID {
		t.Errorf("expected echo context span_id %v, got %v", spanID, capturedEchoSpanID)
	}
}

func TestMiddleware_PreserveIncomingValid(t *testing.T) {
	e := echo.New()
	e.Use(Middleware())

	var capturedTC TraceContext

	e.GET("/order", func(c *echo.Context) error {
		capturedTC = FromContext(c.Request().Context())
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/order", nil)
	req.Header.Set(HeaderXRequestID, "client-req-abc-123")
	req.Header.Set(HeaderTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Set(HeaderTracestate, "rojo=1,congo=2")

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	// Check response headers
	if rec.Header().Get(HeaderXRequestID) != "client-req-abc-123" {
		t.Errorf("expected incoming request ID to be preserved, got %s", rec.Header().Get(HeaderXRequestID))
	}
	if rec.Header().Get(HeaderTracestate) != "rojo=1,congo=2" {
		t.Errorf("expected incoming tracestate to be preserved, got %s", rec.Header().Get(HeaderTracestate))
	}

	// Trace ID must be preserved from caller
	if capturedTC.TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("expected trace ID to be preserved, got %s", capturedTC.TraceID)
	}
	// Parent ID must be the caller's span ID
	if capturedTC.ParentID != "00f067aa0ba902b7" {
		t.Errorf("expected parent ID to be 00f067aa0ba902b7, got %s", capturedTC.ParentID)
	}
	// A new span ID must have been generated for this local execution
	if capturedTC.SpanID == "00f067aa0ba902b7" || len(capturedTC.SpanID) != 16 {
		t.Errorf("expected newly generated 16-hex span ID, got %s", capturedTC.SpanID)
	}
}

func TestMiddleware_SanitizeMaliciousIncoming(t *testing.T) {
	e := echo.New()
	e.Use(Middleware())

	var capturedTC TraceContext

	e.GET("/safe", func(c *echo.Context) error {
		capturedTC = FromContext(c.Request().Context())
		return c.String(http.StatusOK, "ok")
	})

	// CRLF header injection attempt
	req := httptest.NewRequest(http.MethodGet, "/safe", nil)
	req.Header.Set(HeaderXRequestID, "malicious\r\nSet-Cookie: pwned=1")

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	resReqID := rec.Header().Get(HeaderXRequestID)
	if strings.Contains(resReqID, "malicious") || strings.Contains(resReqID, "pwned") {
		t.Errorf("CRLF header was not sanitized, response header: %s", resReqID)
	}
	if !strings.HasPrefix(resReqID, "req-") {
		t.Errorf("expected fresh request ID starting with req-, got: %s", resReqID)
	}
	if capturedTC.RequestID != resReqID {
		t.Errorf("expected context RequestID to match sanitized ID %s, got %s", resReqID, capturedTC.RequestID)
	}
}

func TestMiddleware_TrustIncomingDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustIncoming = false

	e := echo.New()
	e.Use(MiddlewareWithConfig(cfg))

	e.GET("/secure", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set(HeaderXRequestID, "untrusted-client-id")
	req.Header.Set(HeaderTraceparent, "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")

	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	resReqID := rec.Header().Get(HeaderXRequestID)
	if resReqID == "untrusted-client-id" {
		t.Errorf("expected untrusted incoming ID to be ignored, but was preserved")
	}

	resTP := rec.Header().Get(HeaderTraceparent)
	if strings.Contains(resTP, "4bf92f3577b34da6a3ce929d0e0e4736") {
		t.Errorf("expected untrusted incoming traceparent to be ignored, but was preserved")
	}
}
