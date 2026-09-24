package fullstack

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestBreakpoint_TemplNestingAndGCDisable(t *testing.T) {
	// Temporarily disable GC to test raw allocation exhaustion point
	oldGC := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(oldGC)

	depths := []int{10, 100, 500, 1000, 2500, 5000}

	for _, depth := range depths {
		t.Logf("Testing Templ Recursion Depth: %d", depth)

		err := func() (err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("RECOVERED PANIC (System Break): %v", r)
				}
			}()

			comp := MockNestedComponent{Depth: depth}
			ctx := context.Background()

			// Render nested component
			_, errRender := RenderStreamToString(ctx, TurboStreamItem{
				Action:    StreamAppend,
				Target:    "container",
				Component: comp,
			})
			return errRender
		}()

		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		allocMB := float64(m.Alloc) / (1024 * 1024)

		if err != nil {
			t.Logf("💥 BREAKING POINT REACHED AT DEPTH %d! Error: %v, Alloc: %.2fMB", depth, err, allocMB)
			break
		} else {
			t.Logf("Depth %d Passed. Current Heap: %.2fMB", depth, allocMB)
		}
	}
}
