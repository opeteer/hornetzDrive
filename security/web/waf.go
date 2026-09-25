package web

import (
	"net/http"
	"net/url"
	"regexp"

	"github.com/labstack/echo/v5"
)

var (
	// sqliPatterns detects severe SQL Injection payloads
	sqliPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(union\s+select|drop\s+table|exec\s+)`),
	}

	// xssPatterns detects severe Cross-Site Scripting (XSS) payloads
	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(<script>.*</script>|javascript:)`),
	}
)

// WAF returns a lightweight Web Application Firewall middleware that inspects
// request URI only for critical signatures, ensuring maximum request throughput and speed.
func WAF() echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			req := c.Request()
			uri := req.URL.RequestURI()

			// Fast URI check only
			if isMalicious(uri) {
				c.Logger().Warn("WAF blocked malicious URI", "uri", uri, "ip", c.RealIP())
				return echo.NewHTTPError(http.StatusForbidden, "Forbidden: Security policy violation")
			}

			return next(c)
		}
	}
}

// isMalicious checks input string against key attack signatures
func isMalicious(input string) bool {
	if input == "" {
		return false
	}

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

	return false
}

