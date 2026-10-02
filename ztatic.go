package ztatic

import (
	"context"
	"log/slog"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"github.com/redis/go-redis/v9"

	"net/http"
	"reflect"

	"ztatic-go-framework/config"
	"ztatic-go-framework/errors"
	"ztatic-go-framework/filetest"
	"ztatic-go-framework/log"
	"ztatic-go-framework/rapid"
	"ztatic-go-framework/response"
	"ztatic-go-framework/security/audit"
	"ztatic-go-framework/security/crypto"
	"ztatic-go-framework/security/session"
	"ztatic-go-framework/security/token"
	"ztatic-go-framework/security/web"
	"ztatic-go-framework/trace"
	"ztatic-go-framework/upload"
	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
	"ztatic-go-framework/validation"
)

func init() {
	validation.DefaultEngine.Validator().RegisterCustomTypeFunc(func(field reflect.Value) any {
		if s, ok := field.Interface().(config.SecretString); ok {
			return s.Expose()
		}
		return nil
	}, config.SecretString{})
}

// Engine represents the Ztatic Framework engine, wrapping Echo v5
// with enterprise-grade Zero-Trust Security defaults.
type Engine struct {
	*echo.Echo
	wafCfg       *web.WAFConfig // pointer allows SetMaxBodySize to adjust WAF limit after construction
	auditLogger  audit.Logger
	tokenManager *token.Manager
	sessionStore session.Store
	logLevelVar  *slog.LevelVar
}

// AuditLogger returns the active audit logger instance, or nil if disabled.
func (eng *Engine) AuditLogger() audit.Logger {
	return eng.auditLogger
}

// SetAuditLogger sets a custom audit logger on the engine.
func (eng *Engine) SetAuditLogger(l audit.Logger) {
	eng.auditLogger = l
}

// UseAudit mounts the audit logging middleware onto the engine.
func (eng *Engine) UseAudit(cfg audit.AuditConfig) {
	eng.auditLogger = cfg.Logger
	eng.Use(audit.AuditWithConfig(cfg))
}

// TokenManager returns the engine's active token manager.
func (eng *Engine) TokenManager() *token.Manager {
	return eng.tokenManager
}

// SetTokenManager registers a token manager on the engine.
func (eng *Engine) SetTokenManager(tm *token.Manager) {
	eng.tokenManager = tm
}

// UseToken mounts token authentication middleware onto the engine.
func (eng *Engine) UseToken(tm *token.Manager) {
	eng.tokenManager = tm
	eng.Use(token.TokenAuth(tm))
}

// SessionStore returns the active session store on the engine.
func (eng *Engine) SessionStore() session.Store {
	return eng.sessionStore
}

// UseSession mounts session middleware with the specified store onto the engine.
func (eng *Engine) UseSession(store session.Store) {
	eng.sessionStore = store
	eng.Use(session.Middleware(store))
}

// UseSessionWithConfig mounts session middleware with custom configuration.
func (eng *Engine) UseSessionWithConfig(cfg session.SessionConfig) {
	eng.sessionStore = cfg.Store
	eng.Use(session.MiddlewareWithConfig(cfg))
}

// SetLogLevel dynamically changes the engine's structured log severity at runtime.
func (eng *Engine) SetLogLevel(lvl slog.Level) {
	if eng.logLevelVar != nil {
		eng.logLevelVar.Set(lvl)
	}
}

// LogLevel returns the engine's active structured log severity level.
func (eng *Engine) LogLevel() slog.Level {
	if eng.logLevelVar != nil {
		return eng.logLevelVar.Level()
	}
	return slog.LevelInfo
}

// SetCipherSuite configures the AES-256-GCM cipher suite on the engine and sets it as default for field encryption.
func (eng *Engine) SetCipherSuite(cs *crypto.CipherSuite) {
	crypto.SetDefaultCipherSuite(cs)
}

// SetCipherKey initializes an AES-256-GCM cipher suite from a 32-byte key and enables field encryption.
func (eng *Engine) SetCipherKey(key []byte) (*crypto.CipherSuite, error) {
	cs, err := crypto.NewCipherSuite(key)
	if err != nil {
		return nil, err
	}
	crypto.SetDefaultCipherSuite(cs)
	return cs, nil
}

// SetMaxBodySize sets the WAF's maximum allowed request body size in bytes.
// Call this before starting the server. The default is 128 KB (131072 bytes).
//
// Example:
//
//	app := ztatic.NewSecure()
//	app.SetMaxBodySize(4 * 1024 * 1024) // Allow up to 4 MB
//	log.Fatal(app.Start(":8080"))
func (eng *Engine) SetMaxBodySize(bytes int64) {
	if eng.wafCfg != nil {
		eng.wafCfg.MaxBodySize = bytes
	}
}

// TestClient returns a FileTestClient bound to this Engine.
func (eng *Engine) TestClient() *filetest.Client {
	return filetest.NewClient(eng)
}

// DX Type Aliases to match README.md and simplify developer usage
type Context = echo.Context
type HandlerFunc = echo.HandlerFunc
type Map map[string]any
type Group = echo.Group

// Environment & Configuration DX Aliases
type Profile = config.Profile
type SecretString = config.SecretString
type Secret[T any] = config.Secret[T]
type ConfigValidationError = config.ConfigValidationError
type ConfigViolation = config.ConfigViolation
type ConfigOption = config.Option

const (
	ProfileDevelopment = config.ProfileDevelopment
	ProfileTest        = config.ProfileTest
	ProfileStaging     = config.ProfileStaging
	ProfileProduction  = config.ProfileProduction
)

type AuditEntry = audit.Entry
type AuditLogger = audit.Logger
type AuditConfig = audit.AuditConfig

// Token & Session DX Aliases
type Token = token.Token
type TokenManager = token.Manager
type TokenConfig = token.Config
type TokenPair = token.TokenPair
type Claims = token.Claims
type StandardClaims = token.StandardClaims
type GenericClaims[T any] = token.GenericClaims[T]

type Session = session.Session
type SessionStore = session.Store
type SessionConfig = session.SessionConfig
type MemoryStore = session.MemoryStore
type RedisStore = session.RedisStore
type CookieStore = session.CookieStore

type Logger = *slog.Logger
type LogLevel = slog.Level
type LogConfig = log.Config

type TraceContext = trace.TraceContext
type TraceConfig = trace.Config

type AppError = errors.Error
type FieldViolation = errors.FieldViolation
type ErrorConfig = errors.Config

// Error constructors for rapid DX
func NewError(code, message string) *errors.Error { return errors.New(code, message) }
func WrapError(err error, code, message string) *errors.Error { return errors.Wrap(err, code, message) }
func ErrBadRequest(message string) *errors.Error { return errors.BadRequest(message) }
func ErrUnauthorized(message string) *errors.Error { return errors.Unauthorized(message) }
func ErrForbidden(message string) *errors.Error { return errors.Forbidden(message) }
func ErrNotFound(message string) *errors.Error { return errors.NotFound(message) }
func ErrConflict(message string) *errors.Error { return errors.Conflict(message) }
func ErrValidation(message string, violations ...errors.FieldViolation) *errors.Error {
	return errors.Validation(message, violations...)
}
func ErrInternal(message string) *errors.Error { return errors.Internal(message) }
func ErrRateLimited(message string) *errors.Error { return errors.RateLimited(message) }

// Validation & Sanitization DX Aliases
type Validator = validation.Engine
type ContextValidator = validation.ContextValidator
type Sanitizable = validation.Sanitizable
type ContextSanitizable = validation.ContextSanitizable
type CustomValidator = validation.CustomValidator
type SelfValidator = validation.SelfValidator
type DatabaseResolver = validation.DatabaseResolver

// Validation & Sanitization Helper Functions
func Sanitize(i any) error {
	return validation.Sanitize(i)
}

func SanitizeCtx(ctx context.Context, i any) error {
	return validation.SanitizeCtx(ctx, i)
}

func Validate(i any) error {
	return validation.Validate(i)
}

func ValidateCtx(ctx context.Context, i any) error {
	return validation.ValidateCtx(ctx, i)
}

func RegisterValidationRule(tag string, fn validator.Func) {
	validation.RegisterRule(tag, fn)
}

func RegisterValidationRuleWithContext(tag string, fn validator.FuncCtx) {
	validation.RegisterRuleWithContext(tag, fn)
}

func RegisterValidationMessage(rule, template string) {
	validation.RegisterRuleMessage(rule, template)
}

func RegisterValidationFieldMessage(field, rule, template string) {
	validation.RegisterFieldMessage(field, rule, template)
}

func SetDatabaseResolver(resolver validation.DatabaseResolver) {
	validation.SetDatabaseResolver(resolver)
}

func BindAndValidate(c *Context, i any) error {
	return rapid.BindAndValidate(c, i)
}

// Upload & Storage DX Aliases
type Uploader = upload.Manager
type UploadConfig = upload.Config
type ProcessedFile = upload.ProcessedFile
type FileValidationResult = upload.ValidationResult
type FileValidator = upload.Validator
type Storage = storage.Storage
type LocalStorage = storage.LocalStorage
type MemoryStorage = storage.MemoryStorage
type FileRecord = storage.FileRecord
type Scanner = scanner.Scanner
type HeuristicScanner = scanner.HeuristicScanner
type ClamAVScanner = scanner.ClamAVScanner
type MultiScanner = scanner.MultiScanner
type ScanResult = scanner.ScanResult

// Upload constructors and DX helper functions
func NewUploader(cfg upload.Config) (*upload.Manager, error) {
	return upload.NewManager(cfg)
}

func NewLocalStorage(rootDir string) (*storage.LocalStorage, error) {
	return storage.NewLocalStorage(rootDir)
}

func NewMemoryStorage() *storage.MemoryStorage {
	return storage.NewMemoryStorage()
}

func NewHeuristicScanner() *scanner.HeuristicScanner {
	return scanner.NewHeuristicScanner()
}

func NewClamAVScanner(addr string) *scanner.ClamAVScanner {
	return scanner.NewClamAVScanner(addr)
}

func UploadRouteLimit(maxBytes int64) echo.MiddlewareFunc {
	return upload.RouteLimit(maxBytes)
}

func UploadAutoCleanup() echo.MiddlewareFunc {
	return upload.AutoCleanup()
}

type ServeOption = storage.ServeOption

func ServeWithInline() storage.ServeOption { return storage.WithInline() }
func ServeWithDownload() storage.ServeOption { return storage.WithDownload() }
func ServeWithFilename(name string) storage.ServeOption { return storage.WithFilename(name) }

func ServeFile(c *Context, store storage.Storage, key string, opts ...storage.ServeOption) error {
	return storage.ServeHTTP(c, store, key, opts...)
}

// File Testing DX Aliases
type FileTestClient = filetest.Client
type FileTestResponse = filetest.Response
type UploadRequestBuilder = filetest.UploadRequestBuilder
type DownloadRequestBuilder = filetest.DownloadRequestBuilder
type MockStorage = filetest.MockStorage
type MockScanner = filetest.MockScanner
type FileFixture = filetest.FileFixture

func NewFileTestClient(handler http.Handler) *filetest.Client {
	return filetest.NewClient(handler)
}

func NewMockStorage() *filetest.MockStorage {
	return filetest.NewMockStorage()
}

func NewMockScanner() *filetest.MockScanner {
	return filetest.NewMockScanner()
}

// Response & Pagination DX Aliases
type Envelope[T any] = response.Envelope[T]
type ResponseMeta = response.ResponseMeta
type PageParams = response.PageParams
type PaginationMeta = response.PaginationMeta
type CursorParams = response.CursorParams
type CursorMeta = response.CursorMeta
type Links = response.Links
type ResponseConfig = response.Config
type ResponseOption = response.Option

// Response Helper Functions for Rapid DX
func OK(c *Context, data any, opts ...response.Option) error {
	return response.OK(c, data, opts...)
}

func Created(c *Context, data any, location ...string) error {
	return response.Created(c, data, location...)
}

func Accepted(c *Context, data any, opts ...response.Option) error {
	return response.Accepted(c, data, opts...)
}

func NoContent(c *Context) error {
	return response.NoContent(c)
}

func Paginated[T any](c *Context, items []T, meta *response.PaginationMeta, opts ...response.Option) error {
	return response.Paginated(c, items, meta, opts...)
}

func CursorPaginated[T any](c *Context, items []T, meta *response.CursorMeta, opts ...response.Option) error {
	return response.CursorPaginated(c, items, meta, opts...)
}

func ResponseError(c *Context, err error) error {
	return response.Error(c, err)
}

func ExtractPagination(c *Context, opts ...response.PaginationOption) response.PageParams {
	return response.ExtractPagination(c, opts...)
}

func ExtractCursor(c *Context, opts ...response.CursorOption) response.CursorParams {
	return response.ExtractCursor(c, opts...)
}

// Environment & Configuration Helpers

// LoadConfig loads, decodes, and validates environment configuration into T.
func LoadConfig[T any](opts ...config.Option) (*T, error) {
	return config.Load[T](opts...)
}

// MustLoadConfig loads and validates environment configuration into T, panicking on validation failure.
func MustLoadConfig[T any](opts ...config.Option) *T {
	return config.MustLoad[T](opts...)
}

// ActiveProfile returns the active application runtime profile.
func ActiveProfile() config.Profile {
	return config.ActiveProfile()
}

// SetProfile explicitly sets the active application runtime profile.
func SetProfile(p config.Profile) {
	config.SetProfile(p)
}

// NewSecretString initializes an opaque SecretString wrapper.
func NewSecretString(val string) config.SecretString {
	return config.NewSecretString(val)
}

// AuditFromContext retrieves the active audit entry from the request context.
func AuditFromContext(c *Context) *audit.Entry {
	return audit.FromContext(c)
}

// AuditRecord records a domain audit event on the active request context.
func AuditRecord(c *Context, action string, targetType, targetID string) *audit.Entry {
	return audit.Record(c, action, targetType, targetID)
}

// LogFromContext retrieves the request-scoped structured logger from Echo context,
// or returns the framework default logger.
func LogFromContext(c *Context) *slog.Logger {
	if c != nil {
		return c.Logger()
	}
	return log.Default()
}

// TraceFromContext retrieves the distributed trace context from Echo context.
func TraceFromContext(c *Context) trace.TraceContext {
	if c != nil {
		return trace.FromContext(c.Request().Context())
	}
	return trace.TraceContext{}
}

// RequestIDFromContext retrieves the request correlation ID from Echo context.
func RequestIDFromContext(c *Context) string {
	if c != nil {
		return trace.RequestID(c.Request().Context())
	}
	return ""
}

// TraceIDFromContext retrieves the distributed trace ID from Echo context.
func TraceIDFromContext(c *Context) string {
	if c != nil {
		return trace.TraceID(c.Request().Context())
	}
	return ""
}

// SpanIDFromContext retrieves the span ID from Echo context.
func SpanIDFromContext(c *Context) string {
	if c != nil {
		return trace.SpanID(c.Request().Context())
	}
	return ""
}

// TokenFromContext retrieves the verified cryptographic token from the request context.
func TokenFromContext(c *Context) *token.Token {
	return token.FromContext(c)
}

// ClaimsFromContext retrieves the verified claims from the request context.
func ClaimsFromContext(c *Context) *token.Claims {
	return token.ClaimsFromContext(c)
}

// SessionFromContext retrieves the active user session from the request context.
func SessionFromContext(c *Context) *session.Session {
	return session.FromContext(c)
}

// RequireAuth enforces that a valid authenticated token or session exists.
func RequireAuth() echo.MiddlewareFunc {
	return token.RequireAuth()
}

// RequireRole enforces that the authenticated claims contain at least one of the specified roles.
func RequireRole(roles ...string) echo.MiddlewareFunc {
	return token.RequireRole(roles...)
}

// RequireScope enforces that the authenticated claims contain all specified permission scopes.
func RequireScope(scopes ...string) echo.MiddlewareFunc {
	return token.RequireScope(scopes...)
}

// RequireTenant enforces multi-tenant boundary checks.
func RequireTenant(tenantID string) echo.MiddlewareFunc {
	return token.RequireTenant(tenantID)
}

// NewMemorySessionStore creates a thread-safe in-memory session store.
func NewMemorySessionStore() *session.MemoryStore {
	return session.NewMemoryStore()
}

// NewCookieSessionStore creates a stateless AES-256-GCM encrypted cookie session store.
func NewCookieSessionStore(cs *crypto.CipherSuite) (*session.CookieStore, error) {
	return session.NewCookieStore(cs)
}

// NewRedisSessionStore creates a distributed Redis session store.
func NewRedisSessionStore(client redis.UniversalClient) *session.RedisStore {
	return session.NewRedisStore(client)
}

// NewTokenManager creates a token manager with the provided config.
func NewTokenManager(cfg token.Config) (*token.Manager, error) {
	return token.NewManager(cfg)
}

// NewSecure initializes a new Ztatic Engine pre-wired with the complete
// Zero-Trust Web Security Suite. It is safe by default.
func NewSecure() *Engine {
	return NewWithConfig(DefaultConfig())
}

// NewWithConfig initializes a new Ztatic Engine with the provided configuration.
func NewWithConfig(cfg Config) *Engine {
	e := echo.New()

	// Initialize structured logger
	if cfg.Log.LevelVar == nil {
		lvlVar := new(slog.LevelVar)
		lvlVar.Set(cfg.Log.Level)
		cfg.Log.LevelVar = lvlVar
	}
	logInstance := log.New(cfg.Log)
	e.Logger = logInstance
	log.SetDefault(logInstance)

	// Core robust middleware
	e.Use(middleware.Recover())
	e.Use(trace.MiddlewareWithConfig(cfg.Trace))
	e.Use(response.MiddlewareWithConfig(cfg.Response))

	// Phase 1: Structured Request Logger with context correlation and privacy scrubbing
	if cfg.Log.EnableRequestLogger {
		e.Use(log.RequestLoggerWithConfig(log.RequestLoggerConfig{
			Logger:  logInstance,
			Skipper: cfg.Log.Skipper,
		}))
	}

	// Phase 2: Web Security Hardening Pipeline
	if cfg.Security.EnableHeaders {
		e.Use(web.SecureHeadersWithConfig(cfg.Security.Headers))
	}

	// WAFConfig is stored by pointer so SetMaxBodySize can adjust it at runtime.
	wafCfgCopy := cfg.Security.WAF
	if cfg.Security.EnableWAF {
		e.Use(web.WAFWithConfigPtr(&wafCfgCopy))
	}

	if cfg.Security.EnableCSRF {
		e.Use(web.HardenedCSRFWithConfig(cfg.Security.CSRF))
	}

	if cfg.Security.EnableRateLimiter {
		e.Use(web.AdaptiveRateLimiterWithConfig(cfg.Security.RateLimiter))
	}

	var auditLogger audit.Logger
	if cfg.Security.EnableAudit {
		auditCfg := cfg.Security.Audit
		if auditCfg.Logger == nil {
			auditCfg = audit.DefaultAuditConfig()
		}
		auditLogger = auditCfg.Logger
		e.Use(audit.AuditWithConfig(auditCfg))
	}

	var sessionStore session.Store
	if cfg.Session != nil {
		sessionStore = cfg.Session.Store
		e.Use(session.MiddlewareWithConfig(*cfg.Session))
	}

	var tokenManager *token.Manager
	if cfg.Token != nil {
		if tm, err := token.NewManager(*cfg.Token); err == nil {
			tokenManager = tm
			e.Use(token.TokenAuth(tm))
		}
	}

	// Register the high-performance Struct Validator for Rapid DX
	e.Validator = rapid.NewStructValidator()

	// Standardized Error Handling Pipeline
	e.HTTPErrorHandler = errors.NewHTTPErrorHandler(cfg.Error)

	eng := &Engine{
		Echo:         e,
		wafCfg:       &wafCfgCopy,
		auditLogger:  auditLogger,
		tokenManager: tokenManager,
		sessionStore: sessionStore,
		logLevelVar:  cfg.Log.LevelVar,
	}

	// Auto-configure AES-256 field encryption cipher suite if environment variable is present
	if keyStr := os.Getenv("ZTATIC_CIPHER_KEY"); keyStr != "" {
		keyBytes := []byte(keyStr)
		if len(keyBytes) == 32 {
			_, _ = eng.SetCipherKey(keyBytes)
		}
	}

	return eng
}

// New creates a raw Ztatic Engine without the full security pipeline,
// primarily for internal services or APIs behind another gateway.
func New() *Engine {
	e := echo.New()
	e.HTTPErrorHandler = errors.NewHTTPErrorHandler(errors.DefaultConfig())
	e.Use(middleware.Recover())
	e.Use(trace.Middleware())
	e.Use(response.Middleware())
	e.Validator = rapid.NewStructValidator()
	return &Engine{Echo: e}
}
