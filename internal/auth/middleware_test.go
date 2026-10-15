package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestRequireAuth_Unauthorized(t *testing.T) {
	e := echo.New()
	mw := RequireAuth(nil)

	handler := mw(func(c *echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// Remote IP without session
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := handler(c)
	if err == nil && rec.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for remote request without session, got %d", rec.Code)
	}
}

func TestRequireAuth_WithBearerToken(t *testing.T) {
	e := echo.New()
	mw := RequireAuth(nil)

	sessID := CreateUserSession(42)

	handler := mw(func(c *echo.Context) error {
		uid := GetUserID(c)
		if uid != 42 {
			t.Fatalf("Expected user_id 42, got %d", uid)
		}
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.Header.Set("Authorization", "Bearer "+sessID)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := handler(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rec.Code)
	}
}

func TestRequireAuth_WithCookie(t *testing.T) {
	e := echo.New()
	mw := RequireAuth(nil)

	sessID := CreateUserSession(99)

	handler := mw(func(c *echo.Context) error {
		uid := GetUserID(c)
		if uid != 99 {
			t.Fatalf("Expected user_id 99, got %d", uid)
		}
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Forwarded-For", "192.168.1.100")
	req.AddCookie(&http.Cookie{Name: UserSessionCookieName, Value: sessID})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := handler(c); err != nil {
		t.Fatalf("Handler returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d", rec.Code)
	}
}
