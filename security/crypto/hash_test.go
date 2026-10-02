package crypto

import (
	"errors"
	"strings"
	"testing"
)

func TestHashAndVerifyPassword_Success(t *testing.T) {
	password := "SecretP@ssw0rd!2026"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("unexpected error hashing password: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$v=") {
		t.Errorf("expected hash to start with $argon2id$v=, got %q", hash)
	}

	err = VerifyPassword(password, hash)
	if err != nil {
		t.Errorf("expected password verification to succeed, got %v", err)
	}
}

func TestVerifyPassword_Mismatch(t *testing.T) {
	password := "CorrectPassword"
	wrongPassword := "WrongPassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("failed to hash password: %v", err)
	}

	err = VerifyPassword(wrongPassword, hash)
	if !errors.Is(err, ErrHashMismatch) {
		t.Errorf("expected ErrHashMismatch, got %v", err)
	}
}

func TestVerifyPassword_InvalidFormats(t *testing.T) {
	testCases := []struct {
		name        string
		encodedHash string
	}{
		{"empty string", ""},
		{"invalid algorithm", "$bcrypt$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g"},
		{"missing fields", "$argon2id$v=19$m=65536"},
		{"invalid version format", "$argon2id$invalid_version$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g"},
		{"unsupported version number", "$argon2id$v=999$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g"},
		{"malformed params", "$argon2id$v=19$invalid_params$c2FsdHNhbHQ$aGFzaGhhc2g"},
		{"invalid base64 salt", "$argon2id$v=19$m=65536,t=3,p=4$!!!invalid_base64!!!$aGFzaGhhc2g"},
		{"invalid base64 hash", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$!!!invalid_base64!!!"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyPassword("password", tc.encodedHash)
			if !errors.Is(err, ErrInvalidHashFormat) {
				t.Errorf("expected ErrInvalidHashFormat for %s, got %v", tc.name, err)
			}
		})
	}
}

func TestHashPassword_EmptyString(t *testing.T) {
	hash, err := HashPassword("")
	if err != nil {
		t.Fatalf("unexpected error hashing empty password: %v", err)
	}
	if err := VerifyPassword("", hash); err != nil {
		t.Errorf("expected empty password verification to pass, got %v", err)
	}
}
