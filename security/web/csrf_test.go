package web

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestHardenedCSRF_GET_GeneratesTokenCookie(t *testing.T) {
	e := echo.New()
	e.Use(HardenedCSRF())
	e.GET("/form", func(c *echo.Context) error {
		return c.String(http.StatusOK, "form html")
	})

	req := httptest.NewRequest(http.MethodGet, "/form", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200, got %d", rec.Code)
	}

	cookies := rec.Result().Cookies()
	var csrfCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == "_csrf" {
			csrfCookie = cookie
			break
		}
	}

	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Errorf("expected _csrf cookie to be generated on GET request")
	}
}

func TestHardenedCSRF_POST_MissingToken_Forbidden(t *testing.T) {
	e := echo.New()
	e.Use(HardenedCSRF())
	e.POST("/submit", func(c *echo.Context) error {
		return c.String(http.StatusOK, "submitted")
	})

	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusForbidden {
		t.Errorf("expected HTTP 400 or 403 for missing CSRF token on POST, got %d", rec.Code)
	}
}

func TestHardenedCSRF_POST_ValidToken_Success(t *testing.T) {
	e := echo.New()
	e.Use(HardenedCSRF())
	e.GET("/form", func(c *echo.Context) error {
		return c.String(http.StatusOK, "form")
	})
	e.POST("/submit", func(c *echo.Context) error {
		return c.String(http.StatusOK, "success")
	})

	// 1. Get initial token and cookie
	getReq := httptest.NewRequest(http.MethodGet, "/form", nil)
	getRec := httptest.NewRecorder()
	e.ServeHTTP(getRec, getReq)

	var csrfCookie *http.Cookie
	for _, cookie := range getRec.Result().Cookies() {
		if cookie.Name == "_csrf" {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		t.Fatalf("failed to retrieve CSRF cookie from GET request")
	}

	// 2. Submit POST with cookie and X-CSRF-Token header
	postReq := httptest.NewRequest(http.MethodPost, "/submit", nil)
	postReq.AddCookie(csrfCookie)
	postReq.Header.Set("X-CSRF-Token", csrfCookie.Value)
	postRec := httptest.NewRecorder()
	e.ServeHTTP(postRec, postReq)

	if postRec.Code != http.StatusOK {
		t.Errorf("expected HTTP 200 for valid CSRF token POST, got %d", postRec.Code)
	}
}
