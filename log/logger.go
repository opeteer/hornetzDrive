package log

import (
	"context"
	"log/slog"
	"sync"
)

// Re-export common slog types and constants for frictionless DX
type (
	Level = slog.Level
	Attr  = slog.Attr
)

const (
	LevelDebug = slog.LevelDebug
	LevelInfo  = slog.LevelInfo
	LevelWarn  = slog.LevelWarn
	LevelError = slog.LevelError
)

type loggerContextKey struct{}

var (
	globalMu       sync.RWMutex
	globalLogger   *slog.Logger
	globalLevelVar *slog.LevelVar
)

func init() {
	cfg := DefaultConfig()
	globalLevelVar = cfg.LevelVar
	globalLogger = New(cfg)
	slog.SetDefault(globalLogger)
}

// New instantiates a new *slog.Logger configured with the provided Config.
func New(cfg Config) *slog.Logger {
	if cfg.LevelVar == nil {
		lvlVar := new(slog.LevelVar)
		lvlVar.Set(cfg.Level)
		cfg.LevelVar = lvlVar
	}
	handler := NewHandler(cfg)
	return slog.New(handler)
}

// SetDefault replaces the active package-level and global slog logger.
func SetDefault(l *slog.Logger) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLogger = l
	slog.SetDefault(l)
}

// Default returns the active package-level structured logger.
func Default() *slog.Logger {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLogger
}

// SetLevel dynamically changes the package-level log severity at runtime.
func SetLevel(lvl Level) {
	globalMu.Lock()
	defer globalMu.Unlock()
	if globalLevelVar != nil {
		globalLevelVar.Set(lvl)
	}
}

// GetLevel returns the current package-level log severity.
func GetLevel() Level {
	globalMu.RLock()
	defer globalMu.RUnlock()
	if globalLevelVar != nil {
		return globalLevelVar.Level()
	}
	return LevelInfo
}

// LevelVar returns the global *slog.LevelVar instance.
func LevelVar() *slog.LevelVar {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return globalLevelVar
}

// SetLevelVar assigns an external LevelVar to the global logger.
func SetLevelVar(lv *slog.LevelVar) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalLevelVar = lv
}

// WithContext returns a child context carrying the specified *slog.Logger.
func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, loggerContextKey{}, logger)
}

// FromContext retrieves the *slog.Logger from the context, or returns Default() if not found.
func FromContext(ctx context.Context) *slog.Logger {
	if ctx != nil {
		if l, ok := ctx.Value(loggerContextKey{}).(*slog.Logger); ok && l != nil {
			return l
		}
	}
	return Default()
}

// With creates a child logger with the provided attributes attached.
func With(args ...any) *slog.Logger {
	return Default().With(args...)
}

// WithGroup creates a child logger that formats subsequent attributes within a named group.
func WithGroup(name string) *slog.Logger {
	return Default().WithGroup(name)
}

// Debug logs at LevelDebug with the default logger.
func Debug(msg string, args ...any) {
	Default().Debug(msg, args...)
}

// Info logs at LevelInfo with the default logger.
func Info(msg string, args ...any) {
	Default().Info(msg, args...)
}

// Warn logs at LevelWarn with the default logger.
func Warn(msg string, args ...any) {
	Default().Warn(msg, args...)
}

// Error logs at LevelError with the default logger.
func Error(msg string, args ...any) {
	Default().Error(msg, args...)
}

// DebugContext logs at LevelDebug with the given context and default logger.
func DebugContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).DebugContext(ctx, msg, args...)
}

// InfoContext logs at LevelInfo with the given context and default logger.
func InfoContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).InfoContext(ctx, msg, args...)
}

// WarnContext logs at LevelWarn with the given context and default logger.
func WarnContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).WarnContext(ctx, msg, args...)
}

// ErrorContext logs at LevelError with the given context and default logger.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	FromContext(ctx).ErrorContext(ctx, msg, args...)
}
