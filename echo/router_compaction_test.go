package echo

import (
	"net/http"
	"testing"
)

func TestRouter_Compaction(t *testing.T) {
	e := New()
	r := e.router.(*DefaultRouter)

	handler := func(c *Context) error { return nil }

	// 1. Add routes that cause branching
	r.Add(Route{Method: http.MethodGet, Path: "/home", Handler: handler})
	r.Add(Route{Method: http.MethodGet, Path: "/api/v1/users", Handler: handler})
	r.Add(Route{Method: http.MethodGet, Path: "/api/v1/posts", Handler: handler})

	// Tree structure at this point:
	// Root -> "/"
	//   -> "home" (static, handler)
	//   -> "api/v1/" (static, not handler)
	//        -> "users" (static, handler)
	//        -> "posts" (static, handler)

	nodeApiV1 := r.tree.findStaticChild('a')
	if nodeApiV1 == nil || nodeApiV1.prefix != "api/v1/" {
		t.Fatalf("Expected intermediate node 'api/v1/', got prefix: %v", nodeApiV1)
	}
	if len(nodeApiV1.staticChildren) != 2 {
		t.Fatalf("Expected 2 children for 'api/v1/', got %d", len(nodeApiV1.staticChildren))
	}

	// 2. Remove one route, leaving only 1 child
	err := r.Remove(http.MethodGet, "/api/v1/posts")
	if err != nil {
		t.Fatalf("Failed to remove route: %v", err)
	}

	// 3. Compaction should have merged "api/v1/" and "users" into "api/v1/users"
	// Let's verify tree depth and correctness
	nodeApiV1Users := r.tree.findStaticChild('a')
	if nodeApiV1Users == nil || nodeApiV1Users.prefix != "api/v1/users" {
		t.Fatalf("Expected compacted node 'api/v1/users', got prefix: %v", nodeApiV1Users)
	}
	if !nodeApiV1Users.isHandler {
		t.Fatalf("Expected compacted node to be a handler")
	}

	// 4. Test routing still works
	req, _ := http.NewRequest(http.MethodGet, "/api/v1/users", nil)
	c := e.NewContext(req, nil)
	routeHandler := r.Route(c)
	if routeHandler == nil || c.Path() != "/api/v1/users" {
		t.Fatalf("Failed to route to compacted node. Path matched: %s", c.Path())
	}
}

func TestRouter_Compaction_MidTreeHandler(t *testing.T) {
	e := New()
	r := e.router.(*DefaultRouter)

	handler := func(c *Context) error { return nil }

	r.Add(Route{Method: http.MethodGet, Path: "/group", Handler: handler})
	r.Add(Route{Method: http.MethodGet, Path: "/group/item", Handler: handler})

	nodeGroup := r.tree
	if nodeGroup == nil || nodeGroup.prefix != "/group" {
		t.Fatalf("Expected node '/group'")
	}
	if !nodeGroup.isHandler {
		t.Fatalf("Expected '/group' to be handler")
	}
	if len(nodeGroup.staticChildren) != 1 {
		t.Fatalf("Expected 1 child for '/group'")
	}

	// Remove the handler from /group
	err := r.Remove(http.MethodGet, "/group")
	if err != nil {
		t.Fatalf("Failed to remove route: %v", err)
	}

	// After removal, "/group" is no longer a handler, and has 1 child "/item".
	// But it is the root node, and my compaction algorithm does NOT compact the root node (parent == nil).
	// So we expect "/group" and "/item" to remain separate.
	nodeCompacted := r.tree
	if nodeCompacted == nil || nodeCompacted.prefix != "/group" {
		t.Fatalf("Expected root node to remain uncompacted, got %v", nodeCompacted.prefix)
	}
	if nodeCompacted.isHandler {
		t.Fatalf("Expected root node to no longer be a handler")
	}

	// Test routing
	req, _ := http.NewRequest(http.MethodGet, "/group/item", nil)
	c := e.NewContext(req, nil)
	routeHandler := r.Route(c)
	if routeHandler == nil || c.Path() != "/group/item" {
		t.Fatalf("Failed to route to compacted node. Path matched: %s", c.Path())
	}
}
