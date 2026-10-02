package token

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/security/audit"
)

func TestTokenAuth_MiddlewareExtraction(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	mgr, _ := NewManager(DefaultConfig(secret))

	rawToken, _ := mgr.CreateAccessToken(&Claims{
		StandardClaims: StandardClaims{Subject: "user-999"},
		Roles:          []string{"admin"},
		TenantID:       "tenant-xyz",
	})

	setupApp := func() *echo.Echo {
		e := echo.New()
		e.Use(TokenAuth(mgr))
		e.GET("/protected", func(c *echo.Context) error {
			tok := FromContext(c)
			claims := ClaimsFromContext(c)
			if tok == nil || claims == nil {
				return echo.NewHTTPError(http.StatusUnauthorized, "no token in context")
			}
			return c.String(http.StatusOK, "hello "+claims.Subject)
		})
		return e
	}

	app := setupApp()

	// 1. Header extraction: Authorization: Bearer <token>
	req1 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req1.Header.Set("Authorization", "Bearer "+rawToken)
	rec1 := httptest.NewRecorder()
	app.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK || rec1.Body.String() != "hello user-999" {
		t.Fatalf("header extraction failed, got code: %d, body: %s", rec1.Code, rec1.Body.String())
	}

	// 2. Cookie extraction: cookie token=<token>
	req2 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req2.AddCookie(&http.Cookie{Name: "token", Value: rawToken})
	rec2 := httptest.NewRecorder()
	app.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK || rec2.Body.String() != "hello user-999" {
		t.Fatalf("cookie extraction failed, got code: %d", rec2.Code)
	}

	// 3. Query param extraction: ?token=<token>
	req3 := httptest.NewRequest(http.MethodGet, "/protected?token="+rawToken, nil)
	rec3 := httptest.NewRecorder()
	app.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK || rec3.Body.String() != "hello user-999" {
		t.Fatalf("query extraction failed, got code: %d", rec3.Code)
	}

	// 4. Missing token -> 401
	req4 := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rec4 := httptest.NewRecorder()
	app.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on missing token, got: %d", rec4.Code)
	}
}

func TestTokenAuth_AuditIntegration(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	mgr, _ := NewManager(DefaultConfig(secret))

	rawToken, _ := mgr.CreateAccessToken(&Claims{
		StandardClaims: StandardClaims{Subject: "audited-user"},
		Roles:          []string{"auditor"},
		TenantID:       "tenant-1",
	})

	e := echo.New()
	// Pre-populate an audit entry in context to simulate audit middleware
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			entry := audit.NewEntry("test.action")
			c.Set(audit.ContextKeyAuditEntry, entry)
			return next(c)
		}
	})
	e.Use(TokenAuth(mgr))

	e.GET("/audit-test", func(c *echo.Context) error {
		entry := audit.FromContext(c)
		if entry == nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "no audit entry")
		}
		if entry.Actor.ID != "audited-user" || entry.Actor.Role != "auditor" || entry.Actor.TenantID != "tenant-1" {
			t.Errorf("audit actor not enriched: %+v", entry.Actor)
		}
		return c.NoContent(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/audit-test", nil)
	req.Header.Set("Authorization", "Bearer "+rawToken)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestTokenAuth_RouteGuards(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	mgr, _ := NewManager(DefaultConfig(secret))

	userToken, _ := mgr.CreateAccessToken(&Claims{
		StandardClaims: StandardClaims{Subject: "regular-user"},
		Roles:          []string{"user"},
		Scopes:         []string{"read:profile"},
		TenantID:       "tenant-a",
	})

	adminToken, _ := mgr.CreateAccessToken(&Claims{
		StandardClaims: StandardClaims{Subject: "admin-user"},
		Roles:          []string{"admin"},
		Scopes:         []string{"read:profile", "write:profile", "admin:all"},
		TenantID:       "tenant-a",
	})

	e := echo.New()
	e.Use(TokenAuthWithConfig(TokenAuthConfig{
		Manager:  mgr,
		Optional: true, // Let guards do enforcement
	}))

	e.GET("/auth-only", func(c *echo.Context) error {
		return c.String(http.StatusOK, "auth ok")
	}, RequireAuth())

	e.GET("/admin-only", func(c *echo.Context) error {
		return c.String(http.StatusOK, "admin ok")
	}, RequireRole("admin"))

	e.GET("/write-scope", func(c *echo.Context) error {
		return c.String(http.StatusOK, "scope ok")
	}, RequireScope("write:profile"))

	e.GET("/tenant-b", func(c *echo.Context) error {
		return c.String(http.StatusOK, "tenant ok")
	}, RequireTenant("tenant-b"))

	// 1. Unauthenticated to /auth-only -> 401
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth-only", nil)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rec.Code)
	}

	// 2. Regular user to /admin-only -> 403
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}

	// 3. Admin user to /admin-only -> 200
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/admin-only", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	// 4. Scope guard
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/write-scope", nil)
	req.Header.Set("Authorization", "Bearer "+userToken)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 on missing write:profile scope, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/write-scope", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken)
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 on present write:profile scope, got %d", rec.Code)
	}

	// 5. Tenant isolation guard
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/tenant-b", nil)
	req.Header.Set("Authorization", "Bearer "+adminToken) // admin is on tenant-a
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 on mismatched tenant, got %d", rec.Code)
	}
}
