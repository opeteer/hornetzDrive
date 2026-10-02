package fullstack

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

// MockComponent implements the Component shim for testing
type MockComponent struct {
	Content string
}

func (m MockComponent) Render(ctx context.Context, w io.Writer) error {
	_, err := w.Write([]byte(m.Content))
	return err
}

func MockLayout(content Component) Component {
	return MockComponent{
		Content: "<html><body>" + content.(MockComponent).Content + "</body></html>",
	}
}

func TestRender_Standard(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	comp := MockComponent{Content: "<h1>Hello Ztatic</h1>"}

	err := Render(c, 200, comp)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if rec.Code != 200 {
		t.Errorf("Expected status 200, got %d", rec.Code)
	}

	if rec.Header().Get("Content-Type") != "text/html; charset=UTF-8" {
		t.Errorf("Expected HTML content type, got %s", rec.Header().Get("Content-Type"))
	}

	if rec.Body.String() != "<h1>Hello Ztatic</h1>" {
		t.Errorf("Unexpected body: %s", rec.Body.String())
	}
}

func TestRenderLayout_Standard(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	comp := MockComponent{Content: "<div>Content</div>"}

	err := RenderLayout(c, 200, MockLayout, comp)
	if err != nil {
		t.Fatalf("RenderLayout failed: %v", err)
	}

	expected := "<html><body><div>Content</div></body></html>"
	if rec.Body.String() != expected {
		t.Errorf("Expected full layout wrapper, got %s", rec.Body.String())
	}
}

func TestRenderLayout_TurboFrame(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	// Simulate a Turbo Frame request
	req.Header.Set(HeaderTurboFrame, "main_content")
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	comp := MockComponent{Content: "<div>Inner Content Only</div>"}

	err := RenderLayout(c, 200, MockLayout, comp)
	if err != nil {
		t.Fatalf("RenderLayout failed: %v", err)
	}

	// Because HeaderTurboFrame is present, MockLayout should be bypassed
	expected := "<div>Inner Content Only</div>"
	if rec.Body.String() != expected {
		t.Errorf("Expected layout to be unwrapped for Turbo Frame, got %s", rec.Body.String())
	}
}

// Simulates a distinct interface from another package (e.g. github.com/a-h/templ.Component)
type SimulatedTemplComponent interface {
	Render(ctx context.Context, w io.Writer) error
}

func SimulatedTemplLayout(content SimulatedTemplComponent) SimulatedTemplComponent {
	return MockComponent{
		Content: "<templ-shell>" + content.(MockComponent).Content + "</templ-shell>",
	}
}

func TestRenderLayout_TemplFunctionSignature(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	comp := MockComponent{Content: "<p>Article</p>"}

	// SimulatedTemplLayout has signature func(SimulatedTemplComponent) SimulatedTemplComponent
	err := RenderLayout(c, 200, SimulatedTemplLayout, comp)
	if err != nil {
		t.Fatalf("RenderLayout with Templ-style signature failed: %v", err)
	}

	expected := "<templ-shell><p>Article</p></templ-shell>"
	if rec.Body.String() != expected {
		t.Errorf("Expected Templ layout wrapper, got %s", rec.Body.String())
	}
}

type ContextCapturingComponent struct {
	CapturedToken string
}

func (m *ContextCapturingComponent) Render(ctx context.Context, w io.Writer) error {
	m.CapturedToken = CSRFTokenCtx(ctx)
	w.Write([]byte(CSRFFieldCtx(ctx)))
	return nil
}

func TestRender_CSRFContext(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "_csrf", Value: "test-token-12345"})
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	comp := &ContextCapturingComponent{}
	err := Render(c, 200, comp)
	if err != nil {
		t.Fatalf("Render failed: %v", err)
	}

	if comp.CapturedToken != "test-token-12345" {
		t.Errorf("Expected captured token 'test-token-12345', got '%s'", comp.CapturedToken)
	}

	expectedHTML := `<input type="hidden" name="_csrf" value="test-token-12345" />`
	if rec.Body.String() != expectedHTML {
		t.Errorf("Expected rendered CSRF field '%s', got '%s'", expectedHTML, rec.Body.String())
	}
}

