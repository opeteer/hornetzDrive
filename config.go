package ztatic

import (
	"log/slog"

	"ztatic-go-framework/config"
	"ztatic-go-framework/errors"
	"ztatic-go-framework/log"
	"ztatic-go-framework/response"
	"ztatic-go-framework/security/session"
	"ztatic-go-framework/security/token"
	"ztatic-go-framework/security/web"
	"ztatic-go-framework/trace"
)

// Config defines the top-level configuration for the Ztatic engine.
type Config struct {
	// Profile represents the active environment profile (development, test, staging, production).
	Profile config.Profile

	// Security contains the web security suite configuration.
	Security web.Config

	// Trace contains distributed tracing and request correlation configuration.
	Trace trace.Config

	// Log contains the structured logging engine configuration.
	Log log.Config

	// Error contains the standardized error handling configuration.
	Error errors.Config

	// Response contains response envelope and pagination configuration.
	Response response.Config

	// Session contains optional default session configuration.
	Session *session.SessionConfig

	// Token contains optional default token manager configuration.
	Token *token.Config
}

// DefaultConfig returns the default enterprise-grade Zero-Trust configuration.
func DefaultConfig() Config {
	return Config{
		Profile:  config.ActiveProfile(),
		Security: web.DefaultConfig(),
		Trace:    trace.DefaultConfig(),
		Log:      log.DefaultConfig(),
		Error:    errors.DefaultConfig(),
		Response: response.DefaultConfig(),
	}
}

// DefaultConfigForProfile returns a Zero-Trust configuration tailored for the specified profile.
func DefaultConfigForProfile(p config.Profile) Config {
	cfg := DefaultConfig()
	cfg.Profile = p

	if p.IsDevelopment() {
		cfg.Log = log.DefaultDevConfig()
		cfg.Error.ExposeInternalErrors = true
		cfg.Error.EnableStackTrace = true
	} else if p.IsTest() {
		cfg.Log.Level = slog.LevelWarn
		if cfg.Log.LevelVar != nil {
			cfg.Log.LevelVar.Set(slog.LevelWarn)
		}
	} else { // Staging / Production
		cfg.Log.Format = log.FormatJSON
		cfg.Log.Level = slog.LevelInfo
		cfg.Error.ExposeInternalErrors = false
		cfg.Error.EnableStackTrace = false
	}

	return cfg
}

