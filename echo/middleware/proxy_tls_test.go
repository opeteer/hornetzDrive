package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestProxy_TLSConfig(t *testing.T) {
	// Create a mock upstream TLS server
	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("proxied via TLS"))
	}))
	defer backend.Close()

	targetURL, _ := url.Parse(backend.URL)

	// Since backend is a test TLS server, its cert is self-signed
	// So we need to set InsecureSkipVerify to true
	targets := []*ProxyTarget{
		{
			Name: "backend",
			URL:  targetURL,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	proxyMiddleware := ProxyWithConfig(ProxyConfig{
		Balancer: NewRoundRobinBalancer(targets),
	})

	handler := proxyMiddleware(func(c *echo.Context) error {
		return nil
	})

	err := handler(c)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	if rec.Body.String() != "proxied via TLS" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
}
