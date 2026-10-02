package audit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"ztatic-go-framework/security/privacy"
	"ztatic-go-framework/trace"
)

// ContextKeyAuditEntry is the Echo context key holding the active *Entry.
const ContextKeyAuditEntry = "ztatic_audit_entry"

// ActorExtractorFunc extracts actor credentials from an HTTP request context.
type ActorExtractorFunc func(c *echo.Context) Actor

// ActionResolverFunc determines a canonical action identifier from an HTTP request.
type ActionResolverFunc func(c *echo.Context) string

// AuditConfig defines the configuration for the Echo v5 audit logging middleware.
type AuditConfig struct {
	Skipper            middleware.Skipper
	Logger             Logger
	Policy             PolicyFunc
	ActorExtractor     ActorExtractorFunc
	ActionResolver     ActionResolverFunc
	IncludeRequestBody bool
	MaxBodySize        int64
}

// DefaultAuditConfig returns a production-ready audit configuration.
func DefaultAuditConfig() AuditConfig {
	return AuditConfig{
		Skipper:            DefaultAuditSkipper,
		Logger:             NewAsyncLogger(NewJSONFormatter(false), NewStdoutSink(), DefaultAsyncConfig()),
		Policy:             DefaultAuditPolicy,
		ActorExtractor:     DefaultActorExtractor,
		ActionResolver:     DefaultActionResolver,
		IncludeRequestBody: false,
		MaxBodySize:        64 * 1024, // 64 KB limit for body inspection
	}
}

// DefaultActorExtractor extracts the actor identity from request headers or context keys.
func DefaultActorExtractor(c *echo.Context) Actor {
	actor := Actor{
		Type:      "anonymous",
		IP:        c.RealIP(),
		UserAgent: c.Request().UserAgent(),
	}

	req := c.Request()

	// 1. Check custom headers
	if uid := req.Header.Get("X-User-ID"); uid != "" {
		actor.ID = uid
		actor.Type = "user"
	} else if aid := req.Header.Get("X-Actor-ID"); aid != "" {
		actor.ID = aid
		actor.Type = "service_account"
	}

	if tenant := req.Header.Get("X-Tenant-ID"); tenant != "" {
		actor.TenantID = tenant
	}

	if role := req.Header.Get("X-User-Role"); role != "" {
		actor.Role = role
	}

	// 2. Check Echo context bindings (e.g., from auth middleware)
	if val := c.Get("user_id"); val != nil {
		actor.ID = fmt.Sprintf("%v", val)
		actor.Type = "user"
	}
	if val := c.Get("user_role"); val != nil {
		actor.Role = fmt.Sprintf("%v", val)
	}
	if val := c.Get("tenant_id"); val != nil {
		actor.TenantID = fmt.Sprintf("%v", val)
	}

	return actor
}

// DefaultActionResolver generates a canonical audit action like "user.create" from HTTP method & route.
func DefaultActionResolver(c *echo.Context) string {
	method := strings.ToUpper(c.Request().Method)
	path := c.Path()
	if path == "" {
		path = c.Request().URL.Path
	}

	// Clean path into dotted action syntax: e.g. /api/users/:id -> api.users
	cleanPath := strings.Trim(path, "/")
	cleanPath = strings.ReplaceAll(cleanPath, "/", ".")
	cleanPath = strings.ReplaceAll(cleanPath, ":", "")

	switch method {
	case http.MethodGet:
		return "http.read." + cleanPath
	case http.MethodPost:
		return "http.create." + cleanPath
	case http.MethodPut:
		return "http.update." + cleanPath
	case http.MethodPatch:
		return "http.patch." + cleanPath
	case http.MethodDelete:
		return "http.delete." + cleanPath
	default:
		return fmt.Sprintf("http.%s.%s", strings.ToLower(method), cleanPath)
	}
}

// FromContext retrieves the current *Entry from an Echo context.
func FromContext(c *echo.Context) *Entry {
	if val := c.Get(ContextKeyAuditEntry); val != nil {
		if entry, ok := val.(*Entry); ok {
			return entry
		}
	}
	return nil
}

// SetActor updates the actor information on the active request's audit entry.
func SetActor(c *echo.Context, actor Actor) {
	if entry := FromContext(c); entry != nil {
		entry.Actor = actor
	}
}

// Record is a convenience helper for enriching or logging an audit event directly from a handler.
func Record(c *echo.Context, action string, targetType, targetID string) *Entry {
	entry := FromContext(c)
	if entry != nil {
		entry.Action = action
		entry.Target.Type = targetType
		entry.Target.ID = targetID
		return entry
	}
	return nil
}

// Audit returns an audit middleware initialized with default configuration.
func Audit() echo.MiddlewareFunc {
	return AuditWithConfig(DefaultAuditConfig())
}

// AuditWithConfig returns an audit middleware configured with the specified AuditConfig.
func AuditWithConfig(cfg AuditConfig) echo.MiddlewareFunc {
	if cfg.Skipper == nil {
		cfg.Skipper = DefaultAuditConfig().Skipper
	}
	if cfg.Logger == nil {
		cfg.Logger = DefaultAuditConfig().Logger
	}
	if cfg.Policy == nil {
		cfg.Policy = DefaultAuditConfig().Policy
	}
	if cfg.ActorExtractor == nil {
		cfg.ActorExtractor = DefaultActorExtractor
	}
	if cfg.ActionResolver == nil {
		cfg.ActionResolver = DefaultActionResolver
	}
	if cfg.MaxBodySize <= 0 {
		cfg.MaxBodySize = 64 * 1024
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			startTime := time.Now()
			req := c.Request()

			// Extract Request ID and Trace Context
			tc := trace.FromContext(req.Context())
			reqID := tc.RequestID
			if reqID == "" {
				reqID = c.Response().Header().Get(echo.HeaderXRequestID)
				if reqID == "" {
					reqID = req.Header.Get(echo.HeaderXRequestID)
				}
			}

			// Resolve canonical action and actor
			action := cfg.ActionResolver(c)
			actor := cfg.ActorExtractor(c)

			entry := NewEntry(action).
				WithActorStruct(actor).
				WithContext(reqID, req.Method, req.URL.Path, c.Path(), c.RealIP(), req.UserAgent()).
				WithTrace(tc.TraceID, tc.SpanID)

			// Inspect & sanitize request body if enabled
			if cfg.IncludeRequestBody && req.Body != nil && req.ContentLength > 0 && req.ContentLength <= cfg.MaxBodySize {
				bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, cfg.MaxBodySize+1))
				if err == nil && int64(len(bodyBytes)) <= cfg.MaxBodySize {
					req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), req.Body))

					var bodyJSON map[string]any
					if json.Unmarshal(bodyBytes, &bodyJSON) == nil {
						entry.Metadata["request_body"] = privacy.SanitizeMap(bodyJSON)
					}
				}
			}

			// Store entry in context for downstream handler enrichment
			c.Set(ContextKeyAuditEntry, entry)

			// Recover handler panics to guarantee audit visibility before re-panicking
			defer func() {
				if r := recover(); r != nil {
					duration := time.Since(startTime)
					entry.WithDuration(duration)
					if c.Path() != "" {
						entry.Context.Route = c.Path()
					}
					entry.Outcome.StatusCode = http.StatusInternalServerError
					entry.Outcome.Status = OutcomeError
					entry.Severity = SeverityError
					entry.Outcome.Reason = fmt.Sprintf("panic: %v", r)

					if cfg.Policy(c, entry) {
						_ = cfg.Logger.Log(req.Context(), entry)
					}
					// Re-panic so Echo's Recover middleware can handle response committed
					panic(r)
				}
			}()

			// Execute handler chain
			handlerErr := next(c)

			// Response Phase
			duration := time.Since(startTime)
			entry.WithDuration(duration)

			// Update route if matched during routing
			if c.Path() != "" {
				entry.Context.Route = c.Path()
			}

			// Determine status code and outcome
			_, statusCode := echo.ResolveResponseStatus(c.Response(), handlerErr)
			if handlerErr != nil {
				if httpErr, ok := handlerErr.(*echo.HTTPError); ok {
					entry.Outcome.Reason = fmt.Sprintf("%v", httpErr.Message)
				} else {
					entry.Outcome.Reason = handlerErr.Error()
				}
			}

			entry.Outcome.StatusCode = statusCode

			switch {
			case statusCode >= 200 && statusCode < 400:
				entry.Outcome.Status = OutcomeSuccess
			case statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden:
				entry.Outcome.Status = OutcomeDenied
				entry.Severity = SeverityWarn
			case statusCode >= 400 && statusCode < 500:
				entry.Outcome.Status = OutcomeFailure
				entry.Severity = SeverityWarn
			default:
				entry.Outcome.Status = OutcomeError
				entry.Severity = SeverityError
			}

			// Evaluate policy
			if cfg.Policy(c, entry) {
				_ = cfg.Logger.Log(req.Context(), entry)
			}

			return handlerErr
		}
	}
}
