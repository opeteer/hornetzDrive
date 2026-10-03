package web

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/labstack/echo/v5"
)

var (
	// sqliPatterns detects severe SQL Injection payloads
	sqliPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bunion\s*(all\s+|distinct\s+)?select\b`),
		regexp.MustCompile(`(?i)(;\s*|\b(union|select)\b.*?)\b(drop\s+(table|database)|truncate\s+table|alter\s+table)\b`),
		regexp.MustCompile(`(?i)\b(exec|execute)\s*(xp_\w+|sp_\w+|immediate|master\.|\(@?|@\w+)`),
		regexp.MustCompile(`(?i)\b(waitfor\s+delay|pg_sleep\s*\(|sleep\s*\()\b`),
		regexp.MustCompile(`(?i)('\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+'?|'\s*(or|and)\s*'\w+'\s*=\s*'\w+')`),
		regexp.MustCompile(`(?i)('\s*(or|and)\s*.*?--|'\s*--|;\s*--)`),
	}

	// xssPatterns detects severe Cross-Site Scripting (XSS) payloads
	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)<\s*script\b[^>]*>`),
		regexp.MustCompile(`(?is)<\s*/\s*script\s*>`),
		regexp.MustCompile(`(?i)javascript\s*:`),
		regexp.MustCompile(`(?i)\bon(load|error|click|dblclick|mouse\w+|key\w+|focus\w*|blur|change|submit|input|pointer\w+|drag\w+|touch\w+)\s*=`),
		regexp.MustCompile(`(?is)<\s*(iframe|object|embed)\b[^>]*>`),
	}

	// sqlCommentPattern matches SQL inline comments /* ... */
	sqlCommentPattern = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

const maxWAFBodySize = 128 * 1024 // 128KB limit for memory-safe body inspection

// WAF returns a lightweight Web Application Firewall middleware that inspects
// request URI and request body (up to 128KB) for critical signatures, ensuring maximum request throughput and speed.
func WAF() echo.MiddlewareFunc {
	return WAFWithConfig(DefaultWAFConfig())
}

// WAFWithConfig returns a WAF middleware with config.
func WAFWithConfig(cfg WAFConfig) echo.MiddlewareFunc {
	if cfg.Skipper == nil {
		cfg.Skipper = DefaultWAFConfig().Skipper
	}
	maxBody := cfg.MaxBodySize
	if maxBody <= 0 {
		maxBody = maxWAFBodySize
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.Skipper(c) {
				return next(c)
			}

			req := c.Request()
			
			// 1. Check Request URI
			uri := req.URL.RequestURI()
			if isMalicious(uri) {
				c.Logger().Warn("WAF blocked malicious URI", "uri", uri, "ip", c.RealIP())
				return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
			}

			// 2. Check Request Body (for POST/PUT/PATCH with payload, including chunked)
			if req.Body != nil && req.ContentLength != 0 {
				if override, ok := c.Get("ztatic_upload_max_body").(int64); ok && override > 0 {
					maxBody = override
				}
				isUpload, _ := c.Get("ztatic_upload_route").(bool)
				isMultipart := strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/form-data")
				isOctetStream := strings.HasPrefix(req.Header.Get("Content-Type"), "application/octet-stream")
				isUploadPath := strings.HasPrefix(req.URL.Path, "/upload/") || req.URL.Path == "/upload"

				// For multipart file uploads, binary octet-streams, or designated upload routes, avoid buffering binary streams into strings
				if isUpload || isMultipart || isOctetStream || isUploadPath {
					return next(c)
				}

				if req.ContentLength > maxBody {
					c.Logger().Warn("WAF blocked oversized request body", "size", req.ContentLength, "limit", maxBody, "ip", c.RealIP())
					return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Payload Too Large: Security inspection limit exceeded")
				}

				bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
				if err == nil {
					// Restore the body stream immediately for downstream handlers
					req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), req.Body))

					if int64(len(bodyBytes)) > maxBody {
						c.Logger().Warn("WAF blocked oversized body stream", "limit", maxBody, "ip", c.RealIP())
						return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Payload Too Large: Security inspection limit exceeded")
					}

					if len(bodyBytes) > 0 && isMalicious(string(bodyBytes)) {
						c.Logger().Warn("WAF blocked malicious request body", "ip", c.RealIP())
						return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
					}
				}
			}

			return next(c)
		}
	}
}

// WAFWithConfigPtr returns a WAF middleware that reads MaxBodySize from the config pointer
// on every request. This allows Engine.SetMaxBodySize to adjust the WAF body limit
// after the engine is constructed, without rewiring the middleware chain.
func WAFWithConfigPtr(cfg *WAFConfig) echo.MiddlewareFunc {
	skipper := cfg.Skipper
	if skipper == nil {
		skipper = DefaultWAFConfig().Skipper
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if skipper(c) {
				return next(c)
			}

			// Read MaxBodySize dynamically from the pointer so SetMaxBodySize takes effect.
			maxBody := cfg.MaxBodySize
			if maxBody <= 0 {
				maxBody = maxWAFBodySize
			}

			req := c.Request()

			// 1. Check Request URI
			uri := req.URL.RequestURI()
			if isMalicious(uri) {
				c.Logger().Warn("WAF blocked malicious URI", "uri", uri, "ip", c.RealIP())
				return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
			}

			// 2. Check Request Body
			if req.Body != nil && req.ContentLength != 0 {
				if override, ok := c.Get("ztatic_upload_max_body").(int64); ok && override > 0 {
					maxBody = override
				}
				isUpload, _ := c.Get("ztatic_upload_route").(bool)
				isMultipart := strings.HasPrefix(req.Header.Get("Content-Type"), "multipart/form-data")
				isOctetStream := strings.HasPrefix(req.Header.Get("Content-Type"), "application/octet-stream")
				isUploadPath := strings.HasPrefix(req.URL.Path, "/upload/") || req.URL.Path == "/upload"

				// For multipart file uploads, binary octet-streams, or designated upload routes, avoid buffering binary streams into strings
				if isUpload || isMultipart || isOctetStream || isUploadPath {
					return next(c)
				}

				if req.ContentLength > maxBody {
					c.Logger().Warn("WAF blocked oversized request body", "size", req.ContentLength, "limit", maxBody, "ip", c.RealIP())
					return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Payload Too Large: Security inspection limit exceeded")
				}

				// For multipart file uploads or designated upload routes, avoid buffering binary streams into strings
				if isUpload || isMultipart {
					return next(c)
				}

				bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxBody+1))
				if err == nil {
					req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), req.Body))

					if int64(len(bodyBytes)) > maxBody {
						c.Logger().Warn("WAF blocked oversized body stream", "limit", maxBody, "ip", c.RealIP())
						return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Payload Too Large: Security inspection limit exceeded")
					}

					if len(bodyBytes) > 0 && isMalicious(string(bodyBytes)) {
						c.Logger().Warn("WAF blocked malicious request body", "ip", c.RealIP())
						return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
					}
				}
			}

			return next(c)
		}
	}
}

func isHex(c byte) bool {
	return ('0' <= c && c <= '9') || ('a' <= c && c <= 'f') || ('A' <= c && c <= 'F')
}

func unhex(c byte) byte {
	switch {
	case '0' <= c && c <= '9':
		return c - '0'
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10
	}
	return 0
}

func resilientQueryUnescape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '%':
			if i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				b.WriteByte(unhex(s[i+1])<<4 | unhex(s[i+2]))
				i += 2
			} else {
				b.WriteByte('%')
			}
		case '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// recursiveQueryUnescape mitigates double-encoding WAF bypasses resiliently.
func recursiveQueryUnescape(input string) string {
	maxDepth := 5
	prev := input
	for i := 0; i < maxDepth; i++ {
		decoded := resilientQueryUnescape(prev)
		if decoded == prev {
			return prev
		}
		prev = decoded
	}
	return prev
}

// isMalicious checks input string against key attack signatures
func isMalicious(input string) bool {
	if input == "" {
		return false
	}

	// Hardened: mitigate double URL encoding bypass
	input = recursiveQueryUnescape(input)

	// XSS Check
	for _, p := range xssPatterns {
		if p.MatchString(input) {
			return true
		}
	}

	// Strip SQL comments in two formats: collapsed ("") and spaced (" ") to catch split tokens
	inputCommentsSpaced := sqlCommentPattern.ReplaceAllString(input, " ")
	inputCommentsCollapsed := sqlCommentPattern.ReplaceAllString(input, "")

	// SQLi Check
	for _, p := range sqliPatterns {
		if p.MatchString(input) || p.MatchString(inputCommentsSpaced) || p.MatchString(inputCommentsCollapsed) {
			return true
		}
	}

	return false
}

