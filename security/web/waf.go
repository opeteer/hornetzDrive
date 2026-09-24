package web

import (
	"bytes"
	"io"
	"net/http"
	"net/url"
	"regexp"

	"github.com/labstack/echo/v5"
)

const maxWAFBodyInspectSize = 128 * 1024 // Cap inspection at 128 KB to prevent DoS

var (
	// sqliPatterns detects common SQL Injection payloads
	sqliPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|drop\s+table|exec\s+)`),
		regexp.MustCompile(`(?i)('.*'\s*(or|and)\s*'.*'\s*=\s*'.*')`),
		regexp.MustCompile(`(?i)(--;|#|\/\*.*\*\/)`),
	}

	// xssPatterns detects common Cross-Site Scripting (XSS) payloads
	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(<script>.*</script>|javascript:|onerror\s*=|onload\s*=|<img\s+src.*onerror)`),
	}

	// traversalPatterns detects Path Traversal and LFI payloads
	traversalPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(\.\./|\.\.\\|\.\.%2f|%2e%2e%2f)`),
	}
)

// WAF returns a Web Application Firewall middleware that inspects the
// Request URI, Headers, and POST/PUT Body for malicious signatures like SQLi, XSS, and Path Traversal.
func WAF() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := c.Request()
			uri := req.URL.RequestURI()

			// 1. Inspect URI (Path + Query Strings)
			if isMalicious(uri) {
				c.Logger().Warn("WAF blocked malicious URI", "uri", uri, "ip", c.RealIP())
				return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
			}

			// 2. Inspect Headers
			for name, values := range req.Header {
				for _, val := range values {
					if isMalicious(val) {
						c.Logger().Warn("WAF blocked malicious header", "header", name, "ip", c.RealIP())
						return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
					}
				}
			}

			// 3. Inspect Body for state-changing HTTP methods (POST, PUT, PATCH)
			if req.Body != nil && (req.Method == http.MethodPost || req.Method == http.MethodPut || req.Method == http.MethodPatch) {
				// Read body up to maxWAFBodyInspectSize to protect memory
				bodyBytes, err := io.ReadAll(io.LimitReader(req.Body, maxWAFBodyInspectSize))
				if err == nil && len(bodyBytes) > 0 {
					// Re-buffer the body so downstream handlers receive a fresh, unconsumed stream
					req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

					// Inspect body content
					if isMalicious(string(bodyBytes)) {
						c.Logger().Warn("WAF blocked malicious body payload", "method", req.Method, "ip", c.RealIP())
						return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
					}
				}
			}

			return next(c)
		}
	}
}

// isMalicious checks a string against all known attack signatures
func isMalicious(input string) bool {
	if input == "" {
		return false
	}

	// Try to unescape URL encoded payloads
	decoded, err := url.QueryUnescape(input)
	if err == nil {
		input = decoded
	}

	for _, p := range sqliPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	for _, p := range xssPatterns {
		if p.MatchString(input) {
			return true
		}
	}
	for _, p := range traversalPatterns {
		if p.MatchString(input) {
			return true
		}
	}

	return false
}
