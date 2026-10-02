package validation

import (
	"context"
	"errors"
	"testing"
	"time"

	ztaticErrors "ztatic-go-framework/errors"
)

type selfValidatingModel struct {
	Password        string `json:"password" validate:"required,min=6"`
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

func (m *selfValidatingModel) Validate(ctx context.Context) error {
	if m.Password != m.ConfirmPassword {
		return ztaticErrors.Validation("Passwords do not match", ztaticErrors.FieldViolation{
			Field:   "confirm_password",
			Rule:    "matches",
			Message: "Password confirmation does not match",
		})
	}
	return nil
}

type ctxCanceledResolver struct{}

func (c *ctxCanceledResolver) Exists(ctx context.Context, table, column string, value any) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(50 * time.Millisecond):
		return false, nil
	}
}

type cancelSample struct {
	Email string `validate:"unique=users:email"`
}

func TestValidator_CustomValidatorHook(t *testing.T) {
	eng := New()

	// 1. Tag validation fails first
	m1 := &selfValidatingModel{
		Password:        "123",
		ConfirmPassword: "123",
	}
	err := eng.Validate(m1)
	if err == nil {
		t.Fatalf("expected tag min length validation to fail")
	}

	// 2. Tag validation passes, but custom model validation fails
	m2 := &selfValidatingModel{
		Password:        "secure123",
		ConfirmPassword: "different123",
	}
	err = eng.Validate(m2)
	if err == nil {
		t.Fatalf("expected custom validation to fail on password mismatch")
	}
	var appErr *ztaticErrors.Error
	if errors.As(err, &appErr) {
		if appErr.Message != "Passwords do not match" {
			t.Errorf("expected 'Passwords do not match', got '%s'", appErr.Message)
		}
	} else {
		t.Errorf("expected *errors.Error")
	}

	// 3. Both pass
	m3 := &selfValidatingModel{
		Password:        "secure123",
		ConfirmPassword: "secure123",
	}
	if err := eng.Validate(m3); err != nil {
		t.Errorf("expected valid model to pass, got: %v", err)
	}
}

func TestValidator_ContextCancellation(t *testing.T) {
	eng := New()
	eng.SetDatabaseResolver(&ctxCanceledResolver{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	s := cancelSample{Email: "test@example.com"}
	err := eng.ValidateCtx(ctx, &s)
	if err == nil {
		t.Fatalf("expected validation error due to cancelled context")
	}
}

func TestValidator_PackageLevelHelpers(t *testing.T) {
	type simpleInput struct {
		Name string `json:"name" validate:"required"`
	}

	valid := simpleInput{Name: "Alice"}
	if err := Validate(&valid); err != nil {
		t.Errorf("expected valid input to pass, got: %v", err)
	}

	invalid := simpleInput{Name: ""}
	if err := Validate(&invalid); err == nil {
		t.Errorf("expected invalid input to fail")
	}
}
