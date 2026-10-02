package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestLoginMock_SuccessAndFailure(t *testing.T) {
	e := echo.New()

	// 1. Valid password
	validBody := `{"password":"ManusiaIdaman"}`
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(validBody))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := LoginMock(c); err != nil {
		t.Fatalf("LoginMock error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on valid password, got %d", rec.Code)
	}

	// Verify cookie was set
	cookies := rec.Result().Cookies()
	var swarmCookie *http.Cookie
	for _, ck := range cookies {
		if ck.Name == "swarm_session" {
			swarmCookie = ck
			break
		}
	}
	if swarmCookie == nil || swarmCookie.Value == "" {
		t.Fatalf("Expected swarm_session cookie to be set")
	}
	if !GlobalSessionStore.HasKey(swarmCookie.Value) {
		t.Fatalf("Expected key to be stored in GlobalSessionStore")
	}

	// 2. Invalid password
	invalidBody := `{"password":"WrongPassword123"}`
	reqBad := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(invalidBody))
	reqBad.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	recBad := httptest.NewRecorder()
	cBad := e.NewContext(reqBad, recBad)

	if err := LoginMock(cBad); err != nil {
		t.Fatalf("LoginMock error on bad pass: %v", err)
	}
	if recBad.Code != http.StatusUnauthorized {
		t.Fatalf("Expected HTTP 401 on invalid password, got %d", recBad.Code)
	}
}

func TestLockVault(t *testing.T) {
	e := echo.New()

	sessionID := "lock-test-session"
	GlobalSessionStore.SetKey(sessionID, crypto.DummyVK())

	if !GlobalSessionStore.HasKey(sessionID) {
		t.Fatalf("Expected key in session store")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/vault/lock", nil)
	req.AddCookie(&http.Cookie{Name: "swarm_session", Value: sessionID})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	if err := LockVault(c); err != nil {
		t.Fatalf("LockVault error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("Expected HTTP 200 on LockVault, got %d", rec.Code)
	}

	// Verify key was wiped from RAM
	if GlobalSessionStore.HasKey(sessionID) {
		t.Fatalf("Expected key to be removed from GlobalSessionStore after LockVault")
	}
}

