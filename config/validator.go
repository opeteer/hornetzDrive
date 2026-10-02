package config

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"

	"github.com/go-playground/validator/v10"
	ztaticErrors "ztatic-go-framework/errors"
	"ztatic-go-framework/validation"
)

// ConfigValidationError encapsulates all aggregated configuration validation errors.
type ConfigValidationError struct {
	Violations []ConfigViolation
}

// ConfigViolation describes a single configuration constraint violation.
type ConfigViolation struct {
	Field       string
	Rule        string
	Value       any
	Message     string
	Remediation string
}

func (e *ConfigValidationError) Error() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("configuration validation failed with %d error(s):\n", len(e.Violations)))
	for i, v := range e.Violations {
		sb.WriteString(fmt.Sprintf("  [%d] Field: %s | Rule: %s | Message: %s\n", i+1, v.Field, v.Rule, v.Message))
		if v.Remediation != "" {
			sb.WriteString(fmt.Sprintf("      Hint: %s\n", v.Remediation))
		}
	}
	return sb.String()
}

// ConfigValidator validates configuration structs against zero-trust rules.
type ConfigValidator struct {
	engine  *validation.Engine
	profile Profile
}

// NewConfigValidator creates a new ConfigValidator configured for the given profile.
func NewConfigValidator(p Profile) *ConfigValidator {
	eng := validation.New()
	v := eng.Validator()

	// Register custom config validation rules
	v.RegisterCustomTypeFunc(func(field reflect.Value) any {
		if s, ok := field.Interface().(SecretString); ok {
			return s.Expose()
		}
		return nil
	}, SecretString{})

	_ = v.RegisterValidation("config_profile", validateConfigProfile)
	_ = v.RegisterValidation("secure_secret", validateSecureSecret(p))
	_ = v.RegisterValidation("https_url", validateHTTPSURL)
	_ = v.RegisterValidation("db_dsn", validateDatabaseDSN)

	// Register custom messages
	validation.RegisterRuleMessage("config_profile", "must be a recognized profile (development, test, staging, production)")
	validation.RegisterRuleMessage("secure_secret", "must be at least 32 characters in production/staging environments")
	validation.RegisterRuleMessage("https_url", "must be an HTTPS URL")
	validation.RegisterRuleMessage("db_dsn", "must be a valid non-empty database connection string")

	return &ConfigValidator{
		engine:  eng,
		profile: p,
	}
}

// Validate executes struct tag validation, custom config rules, and SelfValidator hooks.
func (cv *ConfigValidator) Validate(cfg any) error {
	if cfg == nil {
		return nil
	}

	ctx := context.Background()

	// 1. Run validation engine
	err := cv.engine.ValidateCtx(ctx, cfg)
	if err != nil {
		var violations []ConfigViolation

		var appErr *ztaticErrors.Error
		if errors.As(err, &appErr) && len(appErr.Details) > 0 {
			for _, d := range appErr.Details {
				violations = append(violations, ConfigViolation{
					Field:       d.Field,
					Rule:        d.Rule,
					Value:       d.Value,
					Message:     d.Message,
					Remediation: fmt.Sprintf("Check the environment variable mapped to %s or fix its value.", d.Field),
				})
			}
		} else {
			violations = append(violations, ConfigViolation{
				Field:       "Config",
				Rule:        "validation",
				Message:     err.Error(),
				Remediation: "Ensure all required environment variables are set and meet schema constraints.",
			})
		}

		return &ConfigValidationError{Violations: violations}
	}

	return nil
}

func validateConfigProfile(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	p := ParseProfile(val)
	return p == ProfileDevelopment || p == ProfileTest || p == ProfileStaging || p == ProfileProduction
}

func validateSecureSecret(p Profile) validator.Func {
	return func(fl validator.FieldLevel) bool {
		var secretLen int
		field := fl.Field()

		if field.Type().String() == "config.SecretString" {
			// Extract Expose length via reflection or interface
			if s, ok := field.Interface().(SecretString); ok {
				secretLen = len(s.Expose())
			}
		} else {
			secretLen = len(field.String())
		}

		// In development or test, allow shorter secrets for convenience
		if p.IsDevelopment() || p.IsTest() {
			return secretLen > 0
		}

		// In production and staging, enforce enterprise minimum 32 bytes (256-bit)
		return secretLen >= 32
	}
}

func validateHTTPSURL(fl validator.FieldLevel) bool {
	field := fl.Field()
	if u, ok := field.Interface().(url.URL); ok {
		return strings.EqualFold(u.Scheme, "https")
	}
	raw := field.String()
	if raw == "" {
		return true
	}
	u, err := url.Parse(raw)
	return err == nil && strings.EqualFold(u.Scheme, "https")
}

func validateDatabaseDSN(fl validator.FieldLevel) bool {
	raw := strings.TrimSpace(fl.Field().String())
	return len(raw) > 5 // Basic sanity check for DSN (e.g. "sqlite::memory:" or "postgres://...")
}
