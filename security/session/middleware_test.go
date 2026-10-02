package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestSessionMiddleware_EndToEnd(t *testing.T) {
	store := NewMemoryStoreWithInterval(0)
	defer store.Close()

	e := echo.New()
	e.Use(Middleware(store))

	// Endpoint 1: Login / Set Session
	e.POST("/login", func(c *echo.Context) error {
		sess := FromContext(c)
		if sess == nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "no session")
		}
		sess.Set("user", "bob")
		sess.Flash("info", "logged in")
		return c.String(http.StatusOK, "ok")
	})

	// Endpoint 2: Read Session Profile
	e.GET("/profile", func(c *echo.Context) error {
		sess := FromContext(c)
		user := sess.GetString("user")
		flashes := sess.Flashes("info")
		flashStr := ""
		if len(flashes) > 0 {
			flashStr = flashes[0].(string)
		}
		return c.JSON(http.StatusOK, map[string]string{
			"user":  user,
			"flash": flashStr,
		})
	})

	// Endpoint 3: Privilege Escalation with Fixation Protection
	e.POST("/escalate", func(c *echo.Context) error {
		sess := FromContext(c)
		_ = sess.RegenerateID() // Session fixation defense
		sess.Set("role", "admin")
		return c.String(http.StatusOK, "escalated")
	})

	// Endpoint 4: Logout
	e.POST("/logout", func(c *echo.Context) error {
		sess := FromContext(c)
		sess.Destroy()
		return c.String(http.StatusOK, "logged out")
	})

	// Step 1: POST /login -> gets Set-Cookie
	req1 := httptest.NewRequest(http.MethodPost, "/login", nil)
	rec1 := httptest.NewRecorder()
	e.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200, got: %d", rec1.Code)
	}

	cookie := rec1.Result().Cookies()
	if len(cookie) == 0 || cookie[0].Name != "ztatic_session" {
		t.Fatalf("expected ztatic_session cookie in response")
	}
	sessionCookie := cookie[0]
	if !sessionCookie.HttpOnly {
		t.Errorf("cookie must have HttpOnly enabled")
	}
	if sessionCookie.SameSite != http.SameSiteLaxMode {
		t.Errorf("expected SameSite Lax")
	}

	// Step 2: GET /profile with cookie -> verifies values and flash
	req2 := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req2.AddCookie(sessionCookie)
	rec2 := httptest.NewRecorder()
	e.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200, got: %d", rec2.Code)
	}
	expectedBody := `{"flash":"logged in","user":"bob"}` + "\n"
	if rec2.Body.String() != expectedBody {
		t.Fatalf("unexpected profile response: %s", rec2.Body.String())
	}

	// Step 3: POST /escalate -> calls RegenerateID()
	req3 := httptest.NewRequest(http.MethodPost, "/escalate", nil)
	req3.AddCookie(sessionCookie)
	rec3 := httptest.NewRecorder()
	e.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusOK {
		t.Fatalf("expected 200, got: %d", rec3.Code)
	}
	cookies3 := rec3.Result().Cookies()
	if len(cookies3) == 0 {
		t.Fatalf("expected new cookie after RegenerateID")
	}
	newSessionCookie := cookies3[0]
	if newSessionCookie.Value == sessionCookie.Value {
		t.Fatalf("session ID did not change after RegenerateID")
	}

	// Verify old session ID was purged from store
	_, err := store.Get(context.Background(), sessionCookie.Value)
	if err != ErrSessionNotFound {
		t.Fatalf("expected old session ID to be purged from store, got: %v", err)
	}

	// Verify new session ID is active in store
	newSess, err := store.Get(context.Background(), newSessionCookie.Value)
	if err != nil {
		t.Fatalf("failed to retrieve new session from store: %v", err)
	}
	if newSess.GetString("user") != "bob" || newSess.GetString("role") != "admin" {
		t.Fatalf("session state corrupted after RegenerateID: %+v", newSess.Values)
	}

	// Step 4: POST /logout -> destroys session
	req4 := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req4.AddCookie(newSessionCookie)
	rec4 := httptest.NewRecorder()
	e.ServeHTTP(rec4, req4)

	if rec4.Code != http.StatusOK {
		t.Fatalf("expected 200, got: %d", rec4.Code)
	}

	// Verify cookie expiration header
	cookies4 := rec4.Result().Cookies()
	if len(cookies4) == 0 || cookies4[0].MaxAge != -1 {
		t.Fatalf("expected cookie deletion with MaxAge: -1")
	}

	// Verify session purged from store
	_, err = store.Get(context.Background(), newSessionCookie.Value)
	if err != ErrSessionNotFound {
		t.Fatalf("expected session to be purged from store after Destroy, got: %v", err)
	}
}
