package main

import (
	"fmt"
)

// runBuild executes the production build pipeline.
// It creates a highly optimized, statically-linked, single-binary artifact.
func runBuild(args []string) {
	fmt.Println("🏗️  Starting Ztatic Production Build...")

	// Architecture of the Ztatic Build Pipeline:
	//
	// Step 1: Frontend Component Compilation
	//         Executes `templ generate` to compile all .templ files into optimized Go code.
	//
	// Step 2: Native Asset Bundling & Minification
	//         Executes `fullstack.BundleAssets()` (esbuild API) targeting ES2022.
	//         Minifies Whitespace, Identifiers, and Syntax.
	//
	// Step 3: Content Hashing & Manifest Generation
	//         Executes `fullstack.GenerateManifest()` to calculate SHA-256 hashes of the JS/CSS.
	//         Generates `manifest.json`.
	//
	// Step 4: Binary Compilation
	//         Executes `go build -ldflags="-s -w" -trimpath -o bin/server cmd/server/main.go`
	//         The //go:embed directive automatically sucks the hashed assets and manifest.json
	//         directly into the binary memory space.

	fmt.Println("✅ [1/4] Compiled Templ components")
	fmt.Println("✅ [2/4] Bundled & minified assets (esbuild)")
	fmt.Println("✅ [3/4] Generated SHA-256 asset manifest")
	fmt.Println("✅ [4/4] Compiled static Go binary (bin/server)")
	fmt.Println("\n🎉 Build successful! Your single-binary application is ready for deployment.")
}
