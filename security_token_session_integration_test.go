package ztatic_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"ztatic-go-framework"
	"ztatic-go-framework/rapid"
	"ztatic-go-framework/security/session"
	"ztatic-go-framework/security/token"
)

func TestIntegration_TokenAndSessionWithAuditAndGuards(t *testing.T) {
	app := ztatic.NewSecure()

	// 1. Configure Session Store
	sessionStore := ztatic.NewMemorySessionStore()
	defer sessionStore.Close()
	app.UseSession(sessionStore)

	// 2. Configure Token Manager
	secret := []byte("01234567890123456789012345678901")
	tokenMgr, err := ztatic.NewTokenManager(token.DefaultConfig(secret))
	if err != nil {
		t.Fatalf("failed to create token manager: %v", err)
	}
	app.SetTokenManager(tokenMgr)

	// 3. Define Routes

	// HTML Session Login
	app.POST("/auth/session-login", func(c *ztatic.Context) error {
		sess := ztatic.SessionFromContext(c)
		sess.Set("user_id", "session-user-1")
		sess.Set("role", "member")
		sess.Flash("welcome", "Welcome back!")
		return c.JSON(http.StatusOK, ztatic.Map{"status": "session created"})
	})

	// HTML Session Profile
	app.GET("/auth/session-profile", func(c *ztatic.Context) error {
		sess := ztatic.SessionFromContext(c)
		userID := sess.GetString("user_id")
		flashes := sess.Flashes("welcome")
		flashStr := ""
		if len(flashes) > 0 {
			flashStr = flashes[0].(string)
		}
		return c.JSON(http.StatusOK, ztatic.Map{
			"user_id": userID,
			"flash":   flashStr,
		})
	})

	// Session Privilege Escalation with Fixation Protection
	app.POST("/auth/session-escalate", func(c *ztatic.Context) error {
		sess := ztatic.SessionFromContext(c)
		_ = sess.RegenerateID() // Session fixation protection
		sess.Set("role", "admin")
		return c.JSON(http.StatusOK, ztatic.Map{"role": "admin"})
	})

	// Token protected API group
	apiGroup := app.Group("/api", token.TokenAuth(tokenMgr))

	// Protected resource guarded by RequireRole
	apiGroup.GET("/admin-data", func(c *ztatic.Context) error {
		claims := ztatic.ClaimsFromContext(c)
		entry := ztatic.AuditFromContext(c)

		// Assert actor automatically captured in audit entry
		actorID := ""
		actorRole := ""
		if entry != nil {
			actorID = entry.Actor.ID
			actorRole = entry.Actor.Role
		}

		return c.JSON(http.StatusOK, ztatic.Map{
			"secret":     "classified",
			"user":       claims.Subject,
			"actor_id":   actorID,
			"actor_role": actorRole,
		})
	}, ztatic.RequireRole("admin"))

	// Protected resource guarded by RequireScope
	apiGroup.GET("/billing-data", func(c *ztatic.Context) error {
		return c.JSON(http.StatusOK, ztatic.Map{"billing": "paid"})
	}, ztatic.RequireScope("billing:read"))

	// -------------------------------------------------------------------------
	// Execution & Verification
	// -------------------------------------------------------------------------

	// Scenario A: Session Lifecycle & Fixation Protection
	// Obtain CSRF token first (standard browser behavior in Ztatic Zero-Trust web)
	app.GET("/csrf-probe", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "csrf ready")
	})
	csrfProbeReq := httptest.NewRequest(http.MethodGet, "/csrf-probe", nil)
	csrfProbeRec := httptest.NewRecorder()
	app.ServeHTTP(csrfProbeRec, csrfProbeReq)

	var csrfCookie *http.Cookie
	for _, ck := range csrfProbeRec.Result().Cookies() {
		if ck.Name == "_csrf" {
			csrfCookie = ck
			break
		}
	}

	// Step A1: POST /auth/session-login with CSRF token
	reqLogin := httptest.NewRequest(http.MethodPost, "/auth/session-login", nil)
	if csrfCookie != nil {
		reqLogin.AddCookie(csrfCookie)
		reqLogin.Header.Set("X-CSRF-Token", csrfCookie.Value)
	}
	recLogin := httptest.NewRecorder()
	app.ServeHTTP(recLogin, reqLogin)

	if recLogin.Code != http.StatusOK {
		t.Fatalf("session login failed, code: %d", recLogin.Code)
	}

	var sessionCookie *http.Cookie
	for _, ck := range recLogin.Result().Cookies() {
		if ck.Name == "ztatic_session" {
			sessionCookie = ck
			break
		}
	}
	if sessionCookie == nil {
		t.Fatalf("expected ztatic_session cookie")
	}

	// Step A2: GET /auth/session-profile
	reqProfile := httptest.NewRequest(http.MethodGet, "/auth/session-profile", nil)
	reqProfile.AddCookie(sessionCookie)
	recProfile := httptest.NewRecorder()
	app.ServeHTTP(recProfile, reqProfile)

	if recProfile.Code != http.StatusOK {
		t.Fatalf("session profile failed, code: %d", recProfile.Code)
	}
	var profileResp map[string]string
	_ = json.Unmarshal(recProfile.Body.Bytes(), &profileResp)
	if profileResp["user_id"] != "session-user-1" || profileResp["flash"] != "Welcome back!" {
		t.Fatalf("unexpected profile resp: %v", profileResp)
	}

	// Step A3: POST /auth/session-escalate (Fixation Defense)
	reqEscalate := httptest.NewRequest(http.MethodPost, "/auth/session-escalate", nil)
	reqEscalate.AddCookie(sessionCookie)
	if csrfCookie != nil {
		reqEscalate.AddCookie(csrfCookie)
		reqEscalate.Header.Set("X-CSRF-Token", csrfCookie.Value)
	}
	recEscalate := httptest.NewRecorder()
	app.ServeHTTP(recEscalate, reqEscalate)

	var newSessionCookie *http.Cookie
	for _, ck := range recEscalate.Result().Cookies() {
		if ck.Name == "ztatic_session" {
			newSessionCookie = ck
			break
		}
	}
	if newSessionCookie == nil {
		t.Fatalf("expected new ztatic_session cookie after escalation")
	}
	if newSessionCookie.Value == sessionCookie.Value {
		t.Fatalf("session fixation vulnerability: session ID was not regenerated!")
	}

	// Verify old session ID was purged from store
	_, err = sessionStore.Get(context.Background(), sessionCookie.Value)
	if err != session.ErrSessionNotFound {
		t.Fatalf("old session ID should have been purged from store")
	}

	// Scenario B: Cryptographic Token Auth, Audit Enrichment, and Role Guards
	// Step B1: Generate Tokens
	memberToken, _ := tokenMgr.CreateAccessToken(&ztatic.Claims{
		StandardClaims: ztatic.StandardClaims{Subject: "token-member"},
		Roles:          []string{"member"},
		Scopes:         []string{"profile:read"},
	})

	adminToken, _ := tokenMgr.CreateAccessToken(&ztatic.Claims{
		StandardClaims: ztatic.StandardClaims{Subject: "token-admin"},
		Roles:          []string{"admin"},
		Scopes:         []string{"profile:read", "billing:read"},
	})

	// Step B2: Member attempts to access /api/admin-data -> 403 Forbidden
	reqForbidden := httptest.NewRequest(http.MethodGet, "/api/admin-data", nil)
	reqForbidden.Header.Set("Authorization", "Bearer "+memberToken)
	recForbidden := httptest.NewRecorder()
	app.ServeHTTP(recForbidden, reqForbidden)

	if recForbidden.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for member on admin route, got: %d", recForbidden.Code)
	}

	// Step B3: Admin accesses /api/admin-data -> 200 OK + Audit Enrichment
	reqAdmin := httptest.NewRequest(http.MethodGet, "/api/admin-data", nil)
	reqAdmin.Header.Set("Authorization", "Bearer "+adminToken)
	recAdmin := httptest.NewRecorder()
	app.ServeHTTP(recAdmin, reqAdmin)

	if recAdmin.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for admin on admin route, got: %d", recAdmin.Code)
	}
	var adminResp map[string]string
	_ = json.Unmarshal(recAdmin.Body.Bytes(), &adminResp)
	if adminResp["user"] != "token-admin" || adminResp["actor_id"] != "token-admin" || adminResp["actor_role"] != "admin" {
		t.Fatalf("audit actor not properly enriched from token: %v", adminResp)
	}

	// Step B4: Scope Guard test
	reqBilling := httptest.NewRequest(http.MethodGet, "/api/billing-data", nil)
	reqBilling.Header.Set("Authorization", "Bearer "+adminToken)
	recBilling := httptest.NewRecorder()
	app.ServeHTTP(recBilling, reqBilling)

	if recBilling.Code != http.StatusOK {
		t.Fatalf("expected 200 for admin with billing:read scope, got: %d", recBilling.Code)
	}

	// Scenario C: OpenAPI Spec includes Security Schemes
	openAPISpec := rapid.DefaultOpenAPIGenerator.BuildOpenAPI(app.Echo)
	components, ok := openAPISpec["components"].(map[string]any)
	if !ok {
		t.Fatalf("missing components in OpenAPI spec")
	}
	secSchemes, ok := components["securitySchemes"].(map[string]any)
	if !ok {
		t.Fatalf("missing securitySchemes in OpenAPI spec")
	}
	if secSchemes["BearerAuth"] == nil || secSchemes["CookieAuth"] == nil {
		t.Fatalf("expected both BearerAuth and CookieAuth in OpenAPI spec, got: %v", secSchemes)
	}
}

func TestIntegration_StatelessEncryptedCookieStore(t *testing.T) {
	app := ztatic.New()

	cipherKey := []byte("01234567890123456789012345678901") // 32 bytes
	cs, err := app.SetCipherKey(cipherKey)
	if err != nil {
		t.Fatal(err)
	}

	cookieStore, err := ztatic.NewCookieSessionStore(cs)
	if err != nil {
		t.Fatal(err)
	}
	app.UseSession(cookieStore)

	app.POST("/set-stateless", func(c *ztatic.Context) error {
		sess := ztatic.SessionFromContext(c)
		sess.Set("theme", "dark")
		sess.Set("user_id", "enc-user-99")
		return c.String(http.StatusOK, "set")
	})

	app.GET("/get-stateless", func(c *ztatic.Context) error {
		sess := ztatic.SessionFromContext(c)
		return c.JSON(http.StatusOK, ztatic.Map{
			"theme":   sess.GetString("theme"),
			"user_id": sess.GetString("user_id"),
		})
	})

	// 1. POST /set-stateless -> receives encrypted cookie
	reqSet := httptest.NewRequest(http.MethodPost, "/set-stateless", nil)
	recSet := httptest.NewRecorder()
	app.ServeHTTP(recSet, reqSet)

	if recSet.Code != http.StatusOK {
		t.Fatalf("set-stateless failed: %d", recSet.Code)
	}

	cookies := recSet.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatalf("expected encrypted cookie")
	}
	encCookie := cookies[0]

	// Verify that the cookie value is encrypted and not raw JSON
	if len(encCookie.Value) < 40 {
		t.Fatalf("encrypted cookie should be high-entropy ciphertext")
	}

	// 2. GET /get-stateless -> decrypts and reads values
	reqGet := httptest.NewRequest(http.MethodGet, "/get-stateless", nil)
	reqGet.AddCookie(encCookie)
	recGet := httptest.NewRecorder()
	app.ServeHTTP(recGet, reqGet)

	if recGet.Code != http.StatusOK {
		t.Fatalf("get-stateless failed: %d", recGet.Code)
	}

	var resp map[string]string
	_ = json.Unmarshal(recGet.Body.Bytes(), &resp)
	if resp["theme"] != "dark" || resp["user_id"] != "enc-user-99" {
		t.Fatalf("failed to decrypt stateless cookie values: %v", resp)
	}
}
