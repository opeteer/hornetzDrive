package fullstack

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestRenderTurboStream_Single(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	comp := MockComponent{Content: "<p>New Message!</p>"}

	err := RenderTurboStream(c, StreamAppend, "messages", comp)
	if err != nil {
		t.Fatalf("RenderTurboStream failed: %v", err)
	}

	if rec.Header().Get("Content-Type") != MIMETurboStream {
		t.Errorf("Expected Turbo Stream MIME type, got %s", rec.Header().Get("Content-Type"))
	}

	expected := `<turbo-stream action="append" target="messages"><template><p>New Message!</p></template></turbo-stream>`
	if rec.Body.String() != expected {
		t.Errorf("Expected\n%s\nGot\n%s", expected, rec.Body.String())
	}
}

func TestRenderTurboStream_Remove(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodDelete, "/item/1", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	// StreamRemove action does not need a component payload
	err := RenderTurboStream(c, StreamRemove, "item_1", nil)
	if err != nil {
		t.Fatalf("RenderTurboStream failed: %v", err)
	}

	expected := `<turbo-stream action="remove" target="item_1"><template></template></turbo-stream>`
	if rec.Body.String() != expected {
		t.Errorf("Expected\n%s\nGot\n%s", expected, rec.Body.String())
	}
}

func TestRenderTurboStreamMulti(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/submit", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	err := RenderTurboStreamMulti(c,
		TurboStreamItem{Action: StreamAppend, Target: "log", Component: MockComponent{Content: "<li>Step 1</li>"}},
		TurboStreamItem{Action: StreamReplace, Target: "status", Component: MockComponent{Content: "<span>Done</span>"}},
	)
	if err != nil {
		t.Fatalf("RenderTurboStreamMulti failed: %v", err)
	}

	expected := `<turbo-stream action="append" target="log"><template><li>Step 1</li></template></turbo-stream><turbo-stream action="replace" target="status"><template><span>Done</span></template></turbo-stream>`
	if rec.Body.String() != expected {
		t.Errorf("Expected\n%s\nGot\n%s", expected, rec.Body.String())
	}
}

func TestRenderStreamToString(t *testing.T) {
	ctx := context.Background()
	item := TurboStreamItem{
		Action:    StreamUpdate,
		Target:    "counter",
		Component: MockComponent{Content: "5"},
	}

	html, err := RenderStreamToString(ctx, item)
	if err != nil {
		t.Fatalf("RenderStreamToString failed: %v", err)
	}

	expected := `<turbo-stream action="update" target="counter"><template>5</template></turbo-stream>`
	if html != expected {
		t.Errorf("Expected %s, got %s", expected, html)
	}
}
