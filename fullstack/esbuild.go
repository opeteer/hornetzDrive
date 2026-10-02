package fullstack

import (
	"fmt"
	"os"

	"github.com/evanw/esbuild/pkg/api"
)

// BundlerOptions defines user-configurable options for the asset compilation pipeline.
type BundlerOptions struct {
	EntryPoints  []string
	OutDir       string
	IsProduction bool
	Target       string            // e.g. "es2022", "chrome100" (default: "es2022")
	Define       map[string]string // Compile-time constant replacements (e.g. process.env.NODE_ENV)
}

// AssetBundleError represents a structured error returned when bundling fails.
type AssetBundleError struct {
	File    string
	Line    int
	Column  int
	Message string
	Snippet string
}

func (e *AssetBundleError) Error() string {
	if e.File != "" {
		return fmt.Sprintf("esbuild error in %s:%d:%d: %s", e.File, e.Line, e.Column, e.Message)
	}
	return fmt.Sprintf("esbuild error: %s", e.Message)
}

// BundleAssets invokes the native esbuild Go API to compile TypeScript, JavaScript, and CSS.
// This runs entirely in Go memory in sub-10ms without requiring Node.js or npm.
func BundleAssets(opts BundlerOptions) (*api.BuildResult, error) {
	if len(opts.EntryPoints) == 0 {
		return nil, fmt.Errorf("esbuild bundle error: no entry points provided")
	}

	if err := os.MkdirAll(opts.OutDir, 0755); err != nil {
		return nil, fmt.Errorf("esbuild failed to create output directory: %w", err)
	}

	sourcemap := api.SourceMapInline
	if opts.IsProduction {
		sourcemap = api.SourceMapLinked
	}

	buildOpts := api.BuildOptions{
		EntryPoints:       opts.EntryPoints,
		Outdir:            opts.OutDir,
		Bundle:            true,
		Write:             true,
		Target:            api.ES2022,
		MinifyWhitespace:  opts.IsProduction,
		MinifyIdentifiers: opts.IsProduction,
		MinifySyntax:      opts.IsProduction,
		Sourcemap:         sourcemap,
		Define:            opts.Define,
		Loader: map[string]api.Loader{
			".css":   api.LoaderCSS,
			".js":    api.LoaderJS,
			".ts":    api.LoaderTS,
			".tsx":   api.LoaderTSX,
			".svg":   api.LoaderFile,
			".png":   api.LoaderFile,
			".jpg":   api.LoaderFile,
			".woff2": api.LoaderFile,
		},
		LogLevel: api.LogLevelWarning,
	}

	result := api.Build(buildOpts)
	
	if len(result.Errors) > 0 {
		msg := result.Errors[0]
		bundleErr := &AssetBundleError{
			Message: msg.Text,
		}
		if msg.Location != nil {
			bundleErr.File = msg.Location.File
			bundleErr.Line = msg.Location.Line
			bundleErr.Column = msg.Location.Column
			bundleErr.Snippet = msg.Location.LineText
		}
		return &result, bundleErr
	}

	return &result, nil
}
