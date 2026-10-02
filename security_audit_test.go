package ztatic_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"ztatic-go-framework"
	"ztatic-go-framework/data"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/rapid"
	"ztatic-go-framework/realtime"
	"ztatic-go-framework/security/crypto"
	"ztatic-go-framework/security/web"
)

// helper to get CSRF token and cookie from NewSecure
func getCSRF(app *ztatic.Engine) (*http.Cookie, string) {
	app.GET("/csrf-token-probe", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	req := httptest.NewRequest(http.MethodGet, "/csrf-token-probe", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "_csrf" {
			return cookie, cookie.Value
		}
	}
	return nil, ""
}

// -----------------------------------------------------------------------------
// 1. WAF REMEDIATION VERIFICATION TESTS
// -----------------------------------------------------------------------------

// TestAudit_WAF_Bypass_BodyOver128KB verifies that oversized request bodies (>128KB)
// are blocked with HTTP 413 (Payload Too Large) to prevent padding bypass attacks.
func TestAudit_WAF_Bypass_BodyOver128KB(t *testing.T) {
	app := ztatic.NewSecure()
	cookie, token := getCSRF(app)

	app.POST("/submit", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "processed")
	})

	// Payload padded to > 128KB (131072 bytes)
	maliciousSQLi := "UNION SELECT username, password FROM users"
	padding := strings.Repeat(" ", 129*1024)
	largeBody := []byte(padding + maliciousSQLi)

	req := httptest.NewRequest(http.MethodPost, "/submit", bytes.NewReader(largeBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(cookie)
	req.ContentLength = int64(len(largeBody))

	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected HTTP 413 Payload Too Large for body > 128KB, got %d", rec.Code)
	}
}

// TestAudit_WAF_Bypass_ChunkedTransferEncoding verifies that chunked transfer encoding
// is properly inspected and malicious payloads are blocked with HTTP 403 Forbidden.
func TestAudit_WAF_Bypass_ChunkedTransferEncoding(t *testing.T) {
	app := ztatic.NewSecure()
	cookie, token := getCSRF(app)

	app.POST("/submit-chunked", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "processed")
	})

	maliciousPayload := []byte(`{"query": "UNION SELECT username, password FROM users"}`)
	req := httptest.NewRequest(http.MethodPost, "/submit-chunked", bytes.NewReader(maliciousPayload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(cookie)
	// Chunked requests have ContentLength = -1
	req.ContentLength = -1

	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for chunked SQLi payload, got %d", rec.Code)
	}
}

// TestAudit_WAF_Bypass_ScriptTagWithAttributes verifies that <script> tags with attributes
// are properly blocked by the hardened WAF.
func TestAudit_WAF_Bypass_ScriptTagWithAttributes(t *testing.T) {
	app := ztatic.NewSecure()
	app.GET("/search", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "results")
	})

	bypasses := []string{
		`/search?q=` + url.QueryEscape(`<script src="//evil.com/xss.js"></script>`),
		`/search?q=` + url.QueryEscape(`<script type="text/javascript">alert(1)</script>`),
		`/search?q=` + url.QueryEscape(`<script defer>alert(1)</script>`),
		`/search?q=` + url.QueryEscape(`<script/src="//evil.com/xss.js"></script>`),
		`/search?q=` + url.QueryEscape(`<iframe src="javascript:alert(1)"></iframe>`),
	}

	for _, uri := range bypasses {
		req := httptest.NewRequest(http.MethodGet, uri, nil)
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected HTTP 403 Forbidden for %s, got %d", uri, rec.Code)
		}
	}
}

// TestAudit_WAF_Bypass_SQLi_UnionAllSelect verifies that UNION ALL SELECT, boolean,
// and time-based SQLi are blocked by the hardened WAF.
func TestAudit_WAF_Bypass_SQLi_UnionAllSelect(t *testing.T) {
	app := ztatic.NewSecure()
	app.GET("/items", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "items")
	})

	sqliPayloads := []string{
		`/items?id=` + url.QueryEscape(`1 UNION ALL SELECT username, password FROM users`),
		`/items?id=` + url.QueryEscape(`1 UNION DISTINCT SELECT username, password FROM users`),
		`/items?id=` + url.QueryEscape(`1' OR '1'='1`),
		`/items?id=` + url.QueryEscape(`1' OR 1=1 -- `),
		`/items?id=` + url.QueryEscape(`1; WAITFOR DELAY '0:0:5'`),
		`/items?id=` + url.QueryEscape(`1; pg_sleep(5)`),
	}

	for _, payload := range sqliPayloads {
		req := httptest.NewRequest(http.MethodGet, payload, nil)
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected HTTP 403 Forbidden for %s, got %d", payload, rec.Code)
		}
	}
}

// TestAudit_WAF_Bypass_CommentObfuscation verifies that comment splitting is detected
// and blocked by the WAF.
func TestAudit_WAF_Bypass_CommentObfuscation(t *testing.T) {
	app := ztatic.NewSecure()
	app.GET("/items", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "items")
	})

	payload := `/items?id=` + url.QueryEscape(`1 UN/**/ION/**/SEL/**/ECT password FROM users`)
	req := httptest.NewRequest(http.MethodGet, payload, nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for comment-split payload, got %d", rec.Code)
	}
}

// TestAudit_WAF_Bypass_RecursiveUnescapeError verifies that invalid URL escape sequences
// do not prevent unescaping valid encoded attack payloads.
func TestAudit_WAF_Bypass_RecursiveUnescapeError(t *testing.T) {
	app := ztatic.NewSecure()
	app.GET("/search", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "ok")
	})

	// %zz would previously break url.QueryUnescape
	payload := `/search?invalid=%zz&q=%253Cscript%253Ealert(1)%253C/script%253E`
	req := httptest.NewRequest(http.MethodGet, payload, nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for resilient unescape payload, got %d", rec.Code)
	}
}

// -----------------------------------------------------------------------------
// 2. HEADERS, CSP, & CSRF CLAIMS VERIFICATION
// -----------------------------------------------------------------------------

// TestAudit_Headers_HSTS_Present verifies that Strict-Transport-Security is injected.
func TestAudit_Headers_HSTS_Present(t *testing.T) {
	app := ztatic.NewSecure()
	app.GET("/ping", func(c *ztatic.Context) error {
		return c.String(http.StatusOK, "pong")
	})

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Fatalf("HSTS header is missing from NewSecure responses!")
	}
}

// TestAudit_CSP_Nonces_Present verifies that CSP nonces are dynamically generated per request.
func TestAudit_CSP_Nonces_Present(t *testing.T) {
	app := ztatic.NewSecure()
	var capturedNonce string
	app.GET("/nonce-test", func(c *ztatic.Context) error {
		capturedNonce = fullstack.Nonce(c)
		return c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/nonce-test", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "'nonce-") {
		t.Fatalf("expected CSP to contain 'nonce-', got: %s", csp)
	}
	if capturedNonce == "" {
		t.Fatalf("expected fullstack.Nonce(c) to return a nonce, got empty")
	}
	if !strings.Contains(csp, "'nonce-"+capturedNonce+"'") {
		t.Fatalf("expected CSP header to contain the captured nonce %q, got: %s", capturedNonce, csp)
	}
}

// TestAudit_CSRF_HardenedDefaults verifies that CSRF defaults use CookieHTTPOnly=true.
func TestAudit_CSRF_HardenedDefaults(t *testing.T) {
	cfg := web.DefaultConfig()
	if !cfg.CSRF.CookieHTTPOnly {
		t.Fatalf("expected CookieHTTPOnly to be true in defaults, got false")
	}
}

// -----------------------------------------------------------------------------
// 3. CRYPTOGRAPHY & DATA PRIVACY INTEGRATION
// -----------------------------------------------------------------------------

// TestAudit_FieldEncryption_Integration verifies EncryptedString and BaseRepository encryption.
func TestAudit_FieldEncryption_Integration(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32-byte key
	cs, err := crypto.NewCipherSuite(key)
	if err != nil {
		t.Fatalf("failed to create cipher suite: %v", err)
	}
	crypto.SetDefaultCipherSuite(cs)

	plaintext := "top-secret-token-xyz"
	encryptedField := crypto.EncryptedString(plaintext)

	// 1. Test driver.Valuer (Database Write)
	val, err := encryptedField.Value()
	if err != nil {
		t.Fatalf("failed to encrypt on Value(): %v", err)
	}
	ciphertext, ok := val.(string)
	if !ok || ciphertext == plaintext || ciphertext == "" {
		t.Fatalf("expected ciphertext string, got: %v", val)
	}

	// 2. Test sql.Scanner (Database Read)
	var decryptedField crypto.EncryptedString
	if err := decryptedField.Scan(ciphertext); err != nil {
		t.Fatalf("failed to decrypt on Scan(): %v", err)
	}
	if string(decryptedField) != plaintext {
		t.Fatalf("expected decrypted string %q, got %q", plaintext, decryptedField)
	}

	// 3. Test BaseRepository model encryption/decryption
	type UserCredentials struct {
		Secret string `ztatic:"encrypt"`
	}
	repo := data.NewBaseRepository[UserCredentials](nil, "users")
	repo.CipherSuite = cs

	model := UserCredentials{Secret: plaintext}
	if err := repo.EncryptModel(&model); err != nil {
		t.Fatalf("failed to encrypt model: %v", err)
	}
	if model.Secret == plaintext {
		t.Fatalf("expected model.Secret to be encrypted, got plaintext")
	}

	if err := repo.DecryptModel(&model); err != nil {
		t.Fatalf("failed to decrypt model: %v", err)
	}
	if model.Secret != plaintext {
		t.Fatalf("expected model.Secret to be decrypted to %q, got %q", plaintext, model.Secret)
	}
}

// -----------------------------------------------------------------------------
// 4. WEBSOCKET CSWSH & TURBO STREAM HTML INJECTION
// -----------------------------------------------------------------------------

// TestAudit_WebSocket_CSWSH_Blocked verifies that cross-origin WebSocket requests are rejected.
func TestAudit_WebSocket_CSWSH_Blocked(t *testing.T) {
	broker := realtime.NewMemoryBroker()
	wsHandler := realtime.WebSocketHandler(broker)

	app := ztatic.New()
	app.GET("/ws", wsHandler)

	ts := httptest.NewServer(app)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws?topic=private-chat"

	// 1. Untrusted Cross-Origin should be rejected with 403 Forbidden
	header := http.Header{}
	header.Set("Origin", "https://attacker-controlled-evil-website.com")

	_, resp, err := websocket.DefaultDialer.Dial(wsURL, header)
	if err == nil {
		t.Fatalf("expected cross-origin WebSocket dial to fail, but it succeeded!")
	}
	if resp != nil && resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 Forbidden for untrusted origin, got %d", resp.StatusCode)
	}

	// 2. Same-Origin connection should succeed with 101 Switching Protocols
	sameOriginHeader := http.Header{}
	sameOriginHeader.Set("Origin", ts.URL)
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, sameOriginHeader)
	if err != nil {
		t.Fatalf("expected same-origin dial to succeed, got: %v", err)
	}
	defer conn.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected 101 Switching Protocols for same-origin, got %d", resp.StatusCode)
	}
}

// TestAudit_TurboStream_AttributeInjection_Fixed verifies that RenderTurboStream
// properly HTML-escapes target and action attributes.
func TestAudit_TurboStream_AttributeInjection_Fixed(t *testing.T) {
	app := ztatic.New()
	app.GET("/stream", func(c *ztatic.Context) error {
		untrustedTarget := `chat-box" onfocus="alert(document.cookie)" tabindex="1`
		return fullstack.RenderTurboStream(c, fullstack.StreamAppend, untrustedTarget, nil)
	})

	req := httptest.NewRequest(http.MethodGet, "/stream", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, `target="chat-box" onfocus="`) {
		t.Fatalf("vulnerability remains: unescaped attribute quotes in stream: %s", body)
	}
	if !strings.Contains(body, `&quot;`) && !strings.Contains(body, `&#34;`) {
		t.Fatalf("expected escaped quotes in target attribute: %s", body)
	}
}

// TestAudit_ScalarUI_XSS_Fixed verifies that ServeDocs HTML-escapes generator Title.
func TestAudit_ScalarUI_XSS_Fixed(t *testing.T) {
	generator := rapid.NewOpenAPIGenerator()
	generator.Title = `Test</title><script>alert('XSS')</script><title>`

	app := ztatic.New()
	generator.ServeDocs(app.Echo, "/docs")

	req := httptest.NewRequest(http.MethodGet, "/docs", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, `Test</title><script>alert('XSS')</script><title> API Reference`) {
		t.Fatalf("vulnerability remains: unescaped script tag in Scalar title: %s", body)
	}
	if !strings.Contains(body, `&lt;script&gt;`) {
		t.Fatalf("expected escaped script tags in title, got: %s", body)
	}
}

// TestAudit_SSE_MultiLineFraming verifies that multi-line Turbo Streams are emitted
// with the proper "data: " prefix on each line.
func TestAudit_SSE_MultiLineFraming(t *testing.T) {
	broker := realtime.NewMemoryBroker()
	app := ztatic.New()
	app.GET("/sse", realtime.SSEHandler(broker))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	req := httptest.NewRequest(http.MethodGet, "/sse?topic=multiline-room", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	go func() {
		// Allow SSE handler to establish connection
		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return
		}

		// Send multi-line HTML message
		_ = broker.Publish(context.Background(), "multiline-room", fullstack.TurboStreamItem{
			Action:    fullstack.StreamAppend,
			Target:    "chat",
			Component: dummyComponentMultiLine{},
		})

		select {
		case <-time.After(50 * time.Millisecond):
		case <-ctx.Done():
			return
		}
		cancel()
	}()

	app.ServeHTTP(rec, req)
	body := rec.Body.String()
	lines := strings.Split(body, "\n")
	hasEvent := false
	dataLineCount := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "event: message") {
			hasEvent = true
		}
		if strings.HasPrefix(l, "data: ") {
			dataLineCount++
		}
	}

	if !hasEvent || dataLineCount < 2 {
		t.Fatalf("expected multi-line SSE message with >= 2 data: lines, got %d data lines. Body:\n%s", dataLineCount, body)
	}
}

type dummyComponentMultiLine struct{}

func (d dummyComponentMultiLine) Render(ctx context.Context, w io.Writer) error {
	_, err := w.Write([]byte("<div>line1</div>\n<div>line2</div>"))
	return err
}
