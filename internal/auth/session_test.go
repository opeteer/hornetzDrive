package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/internal/crypto"
)

func TestVaultKeyMiddleware_StaleCookieFallback(t *testing.T) {
	e := echo.New()
	handlerCalled := false

	h := VaultKeyMiddleware()(func(c *echo.Context) error {
		handlerCalled = true
		vk, ok := c.Get("vault_key").([]byte)
		if !ok || string(vk) != string(crypto.DummyVK()) {
			t.Fatalf("Expected fallback dummy vault key, got: %v", vk)
		}
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodPost, "/upload/init", nil)
	// Attach a stale cookie that is not present in GlobalSessionStore
	req.AddCookie(&http.Cookie{Name: "swarm_session", Value: "stale-session-id-999"})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h(c); err != nil {
		t.Fatalf("Middleware returned error: %v", err)
	}

	if !handlerCalled {
		t.Fatalf("Expected next handler to be called")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200, got %d", rec.Code)
	}
}

func TestVaultKeyMiddleware_ValidSession(t *testing.T) {
	e := echo.New()
	sessionID := "valid-session-123"
	customKey := []byte("customvaultkeycustomvaultkey1234")
	GlobalSessionStore.SetKey(sessionID, customKey)

	handlerCalled := false
	h := VaultKeyMiddleware()(func(c *echo.Context) error {
		handlerCalled = true
		vk, ok := c.Get("vault_key").([]byte)
		if !ok || string(vk) != string(customKey) {
			t.Fatalf("Expected custom vault key, got: %v", vk)
		}
		return c.String(http.StatusOK, "OK")
	})

	req := httptest.NewRequest(http.MethodPost, "/upload/init", nil)
	req.AddCookie(&http.Cookie{Name: "swarm_session", Value: sessionID})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := h(c); err != nil {
		t.Fatalf("Middleware returned error: %v", err)
	}

	if !handlerCalled {
		t.Fatalf("Expected next handler to be called")
	}
}
