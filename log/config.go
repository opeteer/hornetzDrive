package log

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

// Format specifies the output format for structured log records.
type Format string

const (
	// FormatJSON formats log records as single-line JSON objects (NDJSON).
	FormatJSON Format = "json"
	// FormatConsole formats log records with human-readable ANSI color badges.
	FormatConsole Format = "console"
	// FormatText formats log records as key-value pairs (logfmt).
	FormatText Format = "text"
)

// Config defines the configuration for the structured logging engine.
type Config struct {
	// Level is the initial logging severity level. Defaults to slog.LevelInfo.
	Level slog.Level

	// LevelVar is a pointer to an slog.LevelVar enabling atomic runtime level changes.
	// If nil, NewLogger will automatically instantiate one initialized to Level.
	LevelVar *slog.LevelVar

	// Format specifies the output format: FormatJSON, FormatConsole, or FormatText.
	// Defaults to FormatConsole in development (APP_ENV=development), and FormatJSON otherwise.
	Format Format

	// Output is the destination writer for log records. Defaults to os.Stdout.
	Output io.Writer

	// AddSource adds caller source file and line number to log entries.
	// Recommended for debugging and error diagnosis.
	AddSource bool

	// EnablePrivacyMasking automatically wraps the handler with privacy.LogMasker
	// to scrub passwords, tokens, API keys, and sensitive credentials.
	// Defaults to true.
	EnablePrivacyMasking bool

	// EnableRequestLogger automatically mounts the structured HTTP request logger middleware.
	// Defaults to true in NewSecure().
	EnableRequestLogger bool

	// Skipper optionally defines a filter to skip request logging for specific routes.
	// If nil, the default skipper (skipping health checks and static assets) is used.
	Skipper middleware.Skipper
}

// DefaultConfig returns production-ready logging defaults:
// JSON formatting, INFO level, privacy masking enabled, and request logging active.
func DefaultConfig() Config {
	format := FormatJSON
	level := slog.LevelInfo

	// Check environment variables for runtime overrides
	env := strings.ToLower(os.Getenv("APP_ENV"))
	if env == "" {
		env = strings.ToLower(os.Getenv("ZTATIC_ENV"))
	}
	if env == "development" || env == "dev" || env == "local" {
		format = FormatConsole
		level = slog.LevelDebug
	}

	if lvlEnv := os.Getenv("ZTATIC_LOG_LEVEL"); lvlEnv != "" {
		level = parseLevel(lvlEnv, level)
	} else if lvlEnv := os.Getenv("LOG_LEVEL"); lvlEnv != "" {
		level = parseLevel(lvlEnv, level)
	}

	if fmtEnv := os.Getenv("ZTATIC_LOG_FORMAT"); fmtEnv != "" {
		switch strings.ToLower(fmtEnv) {
		case "console", "pretty", "color":
			format = FormatConsole
		case "text", "logfmt":
			format = FormatText
		case "json", "ndjson":
			format = FormatJSON
		}
	}

	levelVar := new(slog.LevelVar)
	levelVar.Set(level)

	return Config{
		Level:                level,
		LevelVar:             levelVar,
		Format:               format,
		Output:               os.Stdout,
		AddSource:            false,
		EnablePrivacyMasking: true,
		EnableRequestLogger:  true,
		Skipper:              DefaultRequestSkipper,
	}
}

// DefaultDevConfig returns a configuration tailored for interactive local development.
func DefaultDevConfig() Config {
	cfg := DefaultConfig()
	cfg.Format = FormatConsole
	cfg.Level = slog.LevelDebug
	if cfg.LevelVar != nil {
		cfg.LevelVar.Set(slog.LevelDebug)
	}
	cfg.AddSource = true
	return cfg
}

func parseLevel(s string, defaultLevel slog.Level) slog.Level {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return slog.LevelDebug
	case "INFO":
		return slog.LevelInfo
	case "WARN", "WARNING":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return defaultLevel
	}
}

// DefaultRequestSkipper skips request logging for high-frequency health probes, metrics, and static assets.
func DefaultRequestSkipper(c *echo.Context) bool {
	path := c.Request().URL.Path
	if path == "/healthz" || path == "/health" || path == "/live" || path == "/ready" || path == "/metrics" || path == "/favicon.ico" {
		return true
	}
	if strings.HasPrefix(path, "/dist/") || strings.HasPrefix(path, "/assets/") {
		return true
	}
	return false
}
