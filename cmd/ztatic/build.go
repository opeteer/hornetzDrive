package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"ztatic-go-framework/fullstack"
)

var (
	buildOutDir   string
	buildEntry    string
	buildAssets   string
	buildDist     string
)

var buildCmd = &cobra.Command{
	Use:   "build",
	Short: "Compile assets and build the optimized production binary",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("🏗️  Starting Ztatic Production Build...")

		// Step 1: Templ generation
		fmt.Println("🔨 [1/4] Compiling Templ components...")
		templCmd := exec.Command("templ", "generate")
		templCmd.Stdout = os.Stdout
		templCmd.Stderr = os.Stderr
		if err := templCmd.Run(); err != nil {
			fmt.Printf("❌ Templ compilation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ [1/4] Compiled Templ components")

		// Step 2: Native Asset Bundling & Minification
		fmt.Println("📦 [2/4] Bundling & minifying assets (esbuild)...")
		
		// Clean destination directory (preserving hidden files like .gitkeep)
		os.MkdirAll(buildDist, 0755)
		if entries, err := os.ReadDir(buildDist); err == nil {
			for _, entry := range entries {
				if !strings.HasPrefix(entry.Name(), ".") {
					_ = os.RemoveAll(filepath.Join(buildDist, entry.Name()))
				}
			}
		}

		var entryPoints []string
		filepath.Walk(buildAssets, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() {
				ext := filepath.Ext(path)
				if ext == ".js" || ext == ".ts" || ext == ".css" {
					entryPoints = append(entryPoints, path)
				}
			}
			return nil
		})

		if len(entryPoints) > 0 {
			opts := fullstack.BundlerOptions{
				EntryPoints:  entryPoints,
				OutDir:       buildDist,
				IsProduction: true,
			}
			if _, err := fullstack.BundleAssets(opts); err != nil {
				fmt.Printf("❌ Asset bundling failed: %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Println("✅ [2/4] Bundled & minified assets")

		// Step 3: Content Hashing & Manifest Generation
		fmt.Println("🗂️  [3/4] Generating SHA-256 asset manifest...")
		os.MkdirAll(buildDist, 0755)
		if _, err := fullstack.GenerateManifest(buildDist); err != nil {
			fmt.Printf("❌ Manifest generation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ [3/4] Generated SHA-256 asset manifest")

		// Step 4: Binary Compilation
		fmt.Printf("🚀 [4/4] Compiling static Go binary (%s)...\n", buildOutDir)
		entry := buildEntry
		if strings.HasSuffix(entry, ".go") {
			entry = filepath.Dir(entry)
		}
		buildCmd := exec.Command("go", "build", "-ldflags=-s -w", "-trimpath", "-o", buildOutDir, entry)
		buildCmd.Stdout = os.Stdout
		buildCmd.Stderr = os.Stderr
		if err := buildCmd.Run(); err != nil {
			fmt.Printf("❌ Binary compilation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("✅ [4/4] Compiled static Go binary")

		fmt.Println("\n🎉 Build successful! Your single-binary application is ready for deployment.")
	},
}

func init() {
	buildCmd.Flags().StringVarP(&buildOutDir, "out", "o", "bin/server", "Destination binary output path")
	buildCmd.Flags().StringVarP(&buildEntry, "entry", "e", "./cmd/server", "Entrypoint Go package for binary build")
	buildCmd.Flags().StringVar(&buildAssets, "assets-dir", "assets", "Asset directory for esbuild bundling")
	buildCmd.Flags().StringVar(&buildDist, "dist-dir", "dist", "Output directory for bundled and content-hashed static assets")
	
	rootCmd.AddCommand(buildCmd)
}
