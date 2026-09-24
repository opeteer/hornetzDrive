package fullstack

import (
	"os"
	"testing"
)

// BenchmarkAssetManager_GetURL_Prod tests the speed of resolving hashed URLs in production.
func BenchmarkAssetManager_GetURL_Prod(b *testing.B) {
	tempDir := b.TempDir()

	manifestContent := `{"css/app.css": "css/app.a8f9b2.css", "js/app.js": "js/app.b7d8c1.js"}`
	os.WriteFile(tempDir+"/manifest.json", []byte(manifestContent), 0644)

	fsys := os.DirFS(tempDir)
	am, _ := NewAssetManager(fsys, false, "/static")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = am.GetURL("css/app.css")
	}
}
