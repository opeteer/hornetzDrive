package validation

import (
	"errors"
	"testing"

	ztaticErrors "ztatic-go-framework/errors"
)

type userRegistrationInput struct {
	Username string `json:"user_name" validate:"required,min=4" message:"required=Username cannot be left blank,min=Username must be at least {param} characters"`
	Email    string `json:"email_address" validate:"required,email" message:"Please provide a valid corporate email address"`
	Age      int    `json:"user_age" validate:"min=18"`
}

type nestedWithMessages struct {
	User userRegistrationInput `json:"user"`
}

func TestMessages_StructTagCustomMessagesAndJSONNames(t *testing.T) {
	eng := New()

	input := userRegistrationInput{
		Username: "bob",           // min=4 failed
		Email:    "not-an-email",  // email failed
		Age:      15,              // min=18 failed (uses default template)
	}

	err := eng.Validate(&input)
	if err == nil {
		t.Fatalf("expected validation error, got nil")
	}

	var appErr *ztaticErrors.Error
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *errors.Error, got %T", err)
	}

	if appErr.Code != ztaticErrors.CodeValidation {
		t.Errorf("expected code %s, got %s", ztaticErrors.CodeValidation, appErr.Code)
	}

	violations := make(map[string]ztaticErrors.FieldViolation)
	for _, v := range appErr.Details {
		violations[v.Field] = v
	}

	// 1. Check user_name (mapped from json tag, custom rule-specific message)
	vUser, ok := violations["user_name"]
	if !ok {
		t.Fatalf("expected violation for 'user_name', details: %+v", appErr.Details)
	}
	if vUser.Message != "Username must be at least 4 characters" {
		t.Errorf("expected custom message 'Username must be at least 4 characters', got '%s'", vUser.Message)
	}

	// 2. Check email_address (mapped from json tag, universal fallback message)
	vEmail, ok := violations["email_address"]
	if !ok {
		t.Fatalf("expected violation for 'email_address', details: %+v", appErr.Details)
	}
	if vEmail.Message != "Please provide a valid corporate email address" {
		t.Errorf("expected custom message 'Please provide a valid corporate email address', got '%s'", vEmail.Message)
	}

	// 3. Check user_age (default template interpolation)
	vAge, ok := violations["user_age"]
	if !ok {
		t.Fatalf("expected violation for 'user_age', details: %+v", appErr.Details)
	}
	if vAge.Message != "Field 'user_age' must be at least 18 in length or value" {
		t.Errorf("expected interpolated default message, got '%s'", vAge.Message)
	}
}

func TestMessages_GlobalOverrides(t *testing.T) {
	eng := New()

	RegisterRuleMessage("alphanum", "{field} only allows letters and numbers")
	RegisterFieldMessage("referral_code", "required", "Referral code is mandatory for this campaign")

	type promoInput struct {
		Code     string `json:"referral_code" validate:"required"`
		Nickname string `json:"nickname" validate:"alphanum"`
	}

	input := promoInput{
		Code:     "",
		Nickname: "hello world!",
	}

	err := eng.Validate(&input)
	if err == nil {
		t.Fatalf("expected validation error")
	}

	var appErr *ztaticErrors.Error
	if !errors.As(err, &appErr) {
		t.Fatalf("expected *errors.Error, got %T", err)
	}

	violations := make(map[string]ztaticErrors.FieldViolation)
	for _, v := range appErr.Details {
		violations[v.Field] = v
	}

	if v, ok := violations["referral_code"]; !ok || v.Message != "Referral code is mandatory for this campaign" {
		t.Errorf("expected registered field message, got %+v", v)
	}
	if v, ok := violations["nickname"]; !ok || v.Message != "nickname only allows letters and numbers" {
		t.Errorf("expected registered rule message, got %+v", v)
	}
}

func TestInterpolate(t *testing.T) {
	tmpl := "Field '{field}' failed on rule '{rule}' with parameter '{param}'. Received '{value}'."
	res := Interpolate(tmpl, "username", "min", "5", "abc")
	expected := "Field 'username' failed on rule 'min' with parameter '5'. Received 'abc'."
	if res != expected {
		t.Errorf("expected '%s', got '%s'", expected, res)
	}
}
