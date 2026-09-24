package fullstack

import (
	"context"
	"io"
	"os"
	"runtime"
	"testing"
)

type MockNestedComponent struct {
	Depth int
}

func (m MockNestedComponent) Render(ctx context.Context, w io.Writer) error {
	w.Write([]byte("<div>"))
	if m.Depth > 0 {
		inner := MockNestedComponent{Depth: m.Depth - 1}
		inner.Render(ctx, w)
	}
	w.Write([]byte("</div>"))
	return nil
}

func TestStress_MemoryLeakAndHeapPressure(t *testing.T) {
	// Setup Asset Manager
	tempDir := t.TempDir()
	os.WriteFile(tempDir+"/manifest.json", []byte(`{"css/app.css": "css/app.hash.css"}`), 0644)
	fsys := os.DirFS(tempDir)
	am, _ := NewAssetManager(fsys, false, "/static")

	// Trigger GC to get a clean baseline
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)

	// Stress Test 1: 5,000,000 Manifest Lookups
	for i := 0; i < 5000000; i++ {
		_ = am.GetURL("css/app.css")
	}

	runtime.ReadMemStats(&m2)
	allocsURL := m2.Mallocs - m1.Mallocs
	bytesURL := m2.TotalAlloc - m1.TotalAlloc

	// Force GC and measure baseline for Render
	runtime.GC()
	runtime.ReadMemStats(&m1)

	// Stress Test 2: Deep Component Nesting (15 levels deep, 50,000 renders)
	ctx := context.Background()
	comp := MockNestedComponent{Depth: 15}
	for i := 0; i < 50000; i++ {
		_, _ = RenderStreamToString(ctx, TurboStreamItem{
			Action:    StreamAppend,
			Target:    "test",
			Component: comp,
		})
	}

	runtime.ReadMemStats(&m2)
	allocsRender := m2.Mallocs - m1.Mallocs
	bytesRender := m2.TotalAlloc - m1.TotalAlloc

	t.Logf("Asset Lookups (5M): Allocs=%d, BytesAllocated=%d", allocsURL, bytesURL)
	t.Logf("Deep Renders (50k): Allocs=%d, BytesAllocated=%d", allocsRender, bytesRender)

	// Assert no runaway heap leaks (RSS check)
	if m2.Alloc > 50*1024*1024 { // 50MB
		t.Errorf("Heap usage too high, potential leak: %d bytes", m2.Alloc)
	}
}
