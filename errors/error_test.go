package errors

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
)

func TestError_ConstructorsAndProperties(t *testing.T) {
	tests := []struct {
		name       string
		err        *Error
		wantCode   string
		wantStatus int
	}{
		{"BadRequest", BadRequest("bad input"), CodeBadRequest, http.StatusBadRequest},
		{"Unauthorized", Unauthorized("unauth"), CodeUnauthorized, http.StatusUnauthorized},
		{"Forbidden", Forbidden("no access"), CodeForbidden, http.StatusForbidden},
		{"NotFound", NotFound("missing"), CodeNotFound, http.StatusNotFound},
		{"Conflict", Conflict("already exists"), CodeConflict, http.StatusConflict},
		{"Validation", Validation("invalid fields"), CodeValidation, http.StatusUnprocessableEntity},
		{"RateLimited", RateLimited("too fast"), CodeRateLimited, http.StatusTooManyRequests},
		{"Internal", Internal("crash"), CodeInternal, http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Code != tc.wantCode {
				t.Errorf("expected code %s, got %s", tc.wantCode, tc.err.Code)
			}
			if tc.err.StatusCode() != tc.wantStatus {
				t.Errorf("expected status %d, got %d", tc.wantStatus, tc.err.StatusCode())
			}
		})
	}
}

func TestError_UnwrapAndIs(t *testing.T) {
	root := errors.New("underlying sql connection failed")
	appErr := Wrap(root, CodeInternal, "failed to query database")

	if !errors.Is(appErr, root) {
		t.Errorf("expected appErr to wrap root error")
	}

	unwrapped := appErr.Unwrap()
	if unwrapped != root {
		t.Errorf("expected unwrapped error to equal root")
	}
}

func TestError_FluentBuilders(t *testing.T) {
	orig := NotFound("user not found")
	modified := orig.
		WithStatus(http.StatusNotFound).
		WithRequestID("req-12345").
		WithMetadata("user_id", 42).
		WithDetails(FieldViolation{
			Field:   "id",
			Rule:    "min",
			Message: "id must be greater than 0",
		})

	if modified.RequestID != "req-12345" {
		t.Errorf("expected request id 'req-12345', got %s", modified.RequestID)
	}
	if modified.Metadata["user_id"] != 42 {
		t.Errorf("expected metadata user_id 42, got %v", modified.Metadata["user_id"])
	}
	if len(modified.Details) != 1 {
		t.Fatalf("expected 1 violation detail, got %d", len(modified.Details))
	}
	if modified.Details[0].Field != "id" {
		t.Errorf("expected detail field 'id', got %s", modified.Details[0].Field)
	}

	// Verify immutability of original
	if orig.RequestID != "" || len(orig.Details) != 0 {
		t.Errorf("expected original error to remain unmodified")
	}
}

func TestError_JSONMarshaling(t *testing.T) {
	root := errors.New("underlying io error")
	appErr := BadRequest("invalid payload").WithInternal(root)

	data, err := json.Marshal(appErr)
	if err != nil {
		t.Fatalf("failed to marshal error: %v", err)
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if m["code"] != CodeBadRequest {
		t.Errorf("expected code %s, got %v", CodeBadRequest, m["code"])
	}
	if m["internal"] != "underlying io error" {
		t.Errorf("expected internal err in JSON marshal, got %v", m["internal"])
	}
}

func TestError_Format(t *testing.T) {
	appErr := Internal("server explosion").WithStack()
	normal := fmt.Sprintf("%v", appErr)
	if normal == "" {
		t.Errorf("expected non-empty formatted string")
	}

	verbose := fmt.Sprintf("%+v", appErr)
	if len(verbose) <= len(normal) {
		t.Errorf("expected verbose format to include stack trace")
	}
}
