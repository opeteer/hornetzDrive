package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

func TestAdaptiveRateLimiter_Allowed(t *testing.T) {
	e := echo.New()
	e.Use(AdaptiveRateLimiter())
	e.GET("/resource", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 for initial request under rate limit, got %d", rec.Code)
	}
}

func TestAdaptiveRateLimiter_Exceeded(t *testing.T) {
	cfg := middleware.RateLimiterConfig{
		Store: middleware.NewRateLimiterMemoryStoreWithConfig(
			middleware.RateLimiterMemoryStoreConfig{
				Rate:      1.0,
				Burst:     2,
				ExpiresIn: 1 * time.Minute,
			},
		),
		IdentifierExtractor: func(c *echo.Context) (string, error) {
			return "test-client-ip", nil
		},
		DenyHandler: func(c *echo.Context, identifier string, err error) error {
			return echo.NewHTTPError(http.StatusTooManyRequests, "Rate limit exceeded")
		},
	}

	e := echo.New()
	e.Use(AdaptiveRateLimiterWithConfig(cfg))
	e.GET("/resource", func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Burst 2 requests should pass
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/resource", nil)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("request %d expected HTTP 200, got %d", i+1, rec.Code)
		}
	}

	// 3rd request should exceed rate limit
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("expected HTTP 429 Too Many Requests when rate limit is exceeded, got %d", rec.Code)
	}
}
