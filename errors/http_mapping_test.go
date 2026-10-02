package errors

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v5"
)

type sampleUser struct {
	Name  string `validate:"required,min=3"`
	Email string `validate:"required,email"`
}

type myCustomErr struct {
	msg string
}

func (e *myCustomErr) Error() string {
	return e.msg
}

func TestMapper_SentinelErrors(t *testing.T) {
	mapper := NewMapper()

	tests := []struct {
		name       string
		err        error
		wantCode   string
		wantStatus int
	}{
		{"sql.ErrNoRows", sql.ErrNoRows, CodeNotFound, http.StatusNotFound},
		{"os.ErrNotExist", os.ErrNotExist, CodeNotFound, http.StatusNotFound},
		{"os.ErrPermission", os.ErrPermission, CodeForbidden, http.StatusForbidden},
		{"context.Canceled", context.Canceled, CodeClientClosed, 499},
		{"context.DeadlineExceeded", context.DeadlineExceeded, CodeGatewayTimeout, http.StatusGatewayTimeout},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := mapper.Map(tc.err)
			if res == nil {
				t.Fatalf("expected non-nil mapped error")
			}
			if res.Code != tc.wantCode {
				t.Errorf("expected code %s, got %s", tc.wantCode, res.Code)
			}
			if res.StatusCode() != tc.wantStatus {
				t.Errorf("expected status %d, got %d", tc.wantStatus, res.StatusCode())
			}
		})
	}
}

func TestMapper_ValidatorErrors(t *testing.T) {
	mapper := NewMapper()
	validate := validator.New()

	u := sampleUser{Name: "a", Email: "invalid-email"}
	err := validate.Struct(u)
	if err == nil {
		t.Fatalf("expected validation error")
	}

	appErr := mapper.Map(err)
	if appErr == nil {
		t.Fatalf("expected non-nil mapped error")
	}

	if appErr.Code != CodeValidation {
		t.Errorf("expected code %s, got %s", CodeValidation, appErr.Code)
	}
	if appErr.StatusCode() != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422, got %d", appErr.StatusCode())
	}
	if len(appErr.Details) != 2 {
		t.Fatalf("expected 2 field violations, got %d", len(appErr.Details))
	}

	fields := map[string]FieldViolation{
		appErr.Details[0].Field: appErr.Details[0],
		appErr.Details[1].Field: appErr.Details[1],
	}

	if v, ok := fields["Name"]; !ok || v.Rule != "min" {
		t.Errorf("expected violation on Name with min rule, got %+v", v)
	}
	if v, ok := fields["Email"]; !ok || v.Rule != "email" {
		t.Errorf("expected violation on Email with email rule, got %+v", v)
	}
}

func TestMapper_EchoHTTPError(t *testing.T) {
	mapper := NewMapper()
	echoErr := echo.NewHTTPError(http.StatusTeapot, "I'm a teapot")

	appErr := mapper.Map(echoErr)
	if appErr.StatusCode() != http.StatusTeapot {
		t.Errorf("expected status 418, got %d", appErr.StatusCode())
	}
	if appErr.Message != "I'm a teapot" {
		t.Errorf("expected message 'I'm a teapot', got %s", appErr.Message)
	}
}

func TestMapper_CustomRegistrations(t *testing.T) {
	mapper := NewMapper()

	var customErr = errors.New("my custom sentinel")
	mapper.RegisterExact(customErr, Conflict("resource conflict occurred"))

	res := mapper.Map(customErr)
	if res.Code != CodeConflict || res.StatusCode() != http.StatusConflict {
		t.Errorf("expected conflict mapping, got %+v", res)
	}

	// Test custom type mapping
	mapper.RegisterType(
		func(e error) bool {
			var ble *myCustomErr
			return errors.As(e, &ble)
		},
		func(e error) *Error {
			return BadRequest("business domain failed").WithInternal(e)
		},
	)

	mappedBle := mapper.Map(&myCustomErr{msg: "order-123"})
	if mappedBle.Code != CodeBadRequest || mappedBle.StatusCode() != http.StatusBadRequest {
		t.Errorf("expected bad request mapping, got %+v", mappedBle)
	}
}

func TestMapper_GenericFallback(t *testing.T) {
	mapper := NewMapper()
	genericErr := errors.New("some unexpected library bug")

	appErr := mapper.Map(genericErr)
	if appErr.Code != CodeInternal {
		t.Errorf("expected internal error code, got %s", appErr.Code)
	}
	if appErr.StatusCode() != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", appErr.StatusCode())
	}
	if !errors.Is(appErr, genericErr) {
		t.Errorf("expected appErr to wrap original error")
	}
}
