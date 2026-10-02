package config

import (
	"errors"
	"strings"
	"testing"
)

type ValidatedConfig struct {
	Env       string       `validate:"config_profile"`
	Port      int          `validate:"required,min=1024,max=65535"`
	SecretKey SecretString `validate:"secure_secret"`
	APIURL    string       `validate:"https_url"`
	DSN       string       `validate:"db_dsn"`
}

type SelfValidatingConfig struct {
	Mode string
}

func (s SelfValidatingConfig) Validate() error {
	if s.Mode == "invalid" {
		return errors.New("mode cannot be invalid")
	}
	return nil
}

func TestConfigValidator_Development(t *testing.T) {
	v := NewConfigValidator(ProfileDevelopment)

	cfg := ValidatedConfig{
		Env:       "development",
		Port:      8080,
		SecretKey: NewSecretString("short-dev-secret"), // allowed in dev
		APIURL:    "https://api.example.com",
		DSN:       "postgres://user:pass@localhost:5432/db",
	}

	if err := v.Validate(cfg); err != nil {
		t.Errorf("expected valid config to pass, got: %v", err)
	}
}

func TestConfigValidator_Production_SecureSecretEnforced(t *testing.T) {
	v := NewConfigValidator(ProfileProduction)

	cfgShort := ValidatedConfig{
		Env:       "production",
		Port:      8080,
		SecretKey: NewSecretString("short-secret"), // < 32 chars, should fail in prod
		APIURL:    "https://api.example.com",
		DSN:       "postgres://user:pass@localhost:5432/db",
	}

	if err := v.Validate(cfgShort); err == nil {
		t.Error("expected short secret to fail in production, got nil error")
	}

	cfgValid := ValidatedConfig{
		Env:       "production",
		Port:      8080,
		SecretKey: NewSecretString("12345678901234567890123456789012"), // 32 chars
		APIURL:    "https://api.example.com",
		DSN:       "postgres://user:pass@localhost:5432/db",
	}

	if err := v.Validate(cfgValid); err != nil {
		t.Errorf("expected 32-byte secret to pass in production, got: %v", err)
	}
}

func TestConfigValidator_HTTPSURL(t *testing.T) {
	v := NewConfigValidator(ProfileProduction)

	cfg := ValidatedConfig{
		Env:       "production",
		Port:      8080,
		SecretKey: NewSecretString("12345678901234567890123456789012"),
		APIURL:    "http://insecure.example.com", // Not HTTPS
		DSN:       "postgres://user:pass@localhost:5432/db",
	}

	err := v.Validate(cfg)
	if err == nil {
		t.Error("expected http URL to fail https_url validation")
	}
}

func TestConfigValidator_SelfValidator(t *testing.T) {
	v := NewConfigValidator(ProfileDevelopment)

	valid := SelfValidatingConfig{Mode: "safe"}
	if err := v.Validate(valid); err != nil {
		t.Errorf("expected valid mode to pass, got: %v", err)
	}

	invalid := SelfValidatingConfig{Mode: "invalid"}
	err := v.Validate(invalid)
	if err == nil {
		t.Error("expected invalid mode to fail SelfValidator")
	} else if !strings.Contains(err.Error(), "mode cannot be invalid") {
		t.Errorf("unexpected error message: %v", err)
	}
}

type MinMaxSecretConfig struct {
	AuthSecret SecretString `validate:"required,min=32"`
}

func TestConfigValidator_SecretString_StandardRules(t *testing.T) {
	v := NewConfigValidator(ProfileDevelopment)

	// Case 1: Short secret (< 32) should fail min=32
	shortCfg := MinMaxSecretConfig{
		AuthSecret: NewSecretString("too-short"),
	}
	if err := v.Validate(shortCfg); err == nil {
		t.Error("expected short SecretString to fail min=32 validation")
	}

	// Case 2: Valid secret (>= 32) should pass min=32
	validCfg := MinMaxSecretConfig{
		AuthSecret: NewSecretString("dev-secret-key-must-be-changed-in-production-min-32-bytes"),
	}
	if err := v.Validate(validCfg); err != nil {
		t.Errorf("expected valid SecretString to pass min=32 validation, got: %v", err)
	}

	// Case 3: Empty secret should fail required
	emptyCfg := MinMaxSecretConfig{
		AuthSecret: NewSecretString(""),
	}
	if err := v.Validate(emptyCfg); err == nil {
		t.Error("expected empty SecretString to fail required validation")
	}
}
