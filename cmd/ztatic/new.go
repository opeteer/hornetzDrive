package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var newDir string

var newCmd = &cobra.Command{
	Use:   "new <name>",
	Short: "Scaffold a new Ztatic project architecture",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		projectName := args[0]
		// Derive a valid Go module name: use only the base segment so that absolute
		// paths like "/tmp/myapp" or "../myapp" produce "module myapp" in go.mod.
		moduleName := filepath.Base(filepath.ToSlash(projectName))
		if moduleName == "." || moduleName == "/" || moduleName == "" {
			fmt.Printf("❌ Invalid project name %q — please use a simple name like 'myapp'\n", projectName)
			os.Exit(1)
		}
		fmt.Printf("🚀 Scaffolding new Ztatic project: %s\n", moduleName)

		baseDir := filepath.Join(newDir, projectName)
		absBaseDir, err := filepath.Abs(baseDir)
		if err != nil {
			absBaseDir = baseDir
		}

		// Define the standard architectural directory structure
		dirs := []string{
			"cmd/server",
			"internal/controllers",
			"internal/config",
			"internal/models",
			"internal/repositories",
			"internal/views/layouts",
			"internal/views/components",
			"assets/css",
			"assets/js",
			"db/migrations",
			"dist",
		}

		// Create directories
		for _, dir := range dirs {
			path := filepath.Join(baseDir, dir)
			if err := os.MkdirAll(path, 0755); err != nil {
				fmt.Printf("Error creating directory %s: %v\n", path, err)
				os.Exit(1)
			}
		}

		// Create placeholder in dist directory so embed.FS or tools do not fail
		_ = os.WriteFile(filepath.Join(baseDir, "dist", ".gitkeep"), []byte(""), 0644)

		// Generate dist.go in project root to support single-binary //go:embed all:dist
		distGoContent := fmt.Sprintf(`package %s

import "embed"

// DistFS embeds compiled static assets for zero-dependency single-binary deployment
//go:embed all:dist
var DistFS embed.FS
`, moduleName)
		if err := os.WriteFile(filepath.Join(baseDir, "dist.go"), []byte(distGoContent), 0644); err != nil {
			fmt.Printf("Error writing dist.go: %v\n", err)
		}

		// Generate internal/config/config.go
		configGoContent := `package config

import (
	"ztatic-go-framework"
)

// AppConfig defines the type-safe environment configuration schema for this application.
type AppConfig struct {
	AppName     string              ` + "`" + `env:"APP_NAME" envDefault:"myapp" validate:"required"` + "`" + `
	Port        string              ` + "`" + `env:"PORT" envDefault:"8080" validate:"required"` + "`" + `
	DatabaseDSN string              ` + "`" + `env:"DATABASE_DSN" envDefault:"app.db" validate:"required"` + "`" + `
	CipherKey   ztatic.SecretString ` + "`" + `env:"ZTATIC_CIPHER_KEY" envDefault:"01234567890123456789012345678901"` + "`" + `
	AuthSecret  ztatic.SecretString ` + "`" + `env:"AUTH_SECRET" envDefault:"dev-secret-key-must-be-changed-in-production-min-32-bytes" validate:"required,min=32"` + "`" + `
}
`
		if err := os.WriteFile(filepath.Join(baseDir, "internal/config", "config.go"), []byte(configGoContent), 0644); err != nil {
			fmt.Printf("Error writing internal/config/config.go: %v\n", err)
		}

		// Generate .env and .env.example
		envContent := fmt.Sprintf(`APP_NAME=%s
PORT=8080
DATABASE_DSN=app.db
ZTATIC_CIPHER_KEY=01234567890123456789012345678901
AUTH_SECRET=dev-secret-key-must-be-changed-in-production-min-32-bytes
`, moduleName)
		_ = os.WriteFile(filepath.Join(baseDir, ".env"), []byte(envContent), 0644)

		envExampleContent := `APP_NAME=myapp
PORT=8080
DATABASE_DSN=app.db
ZTATIC_CIPHER_KEY=01234567890123456789012345678901
AUTH_SECRET=your-production-secret-must-be-at-least-32-bytes
`
		_ = os.WriteFile(filepath.Join(baseDir, ".env.example"), []byte(envExampleContent), 0644)

		// Generate main.go stub
		mainContent := fmt.Sprintf(`package main

import (
	"io/fs"
	"os"

	"ztatic-go-framework"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/log"
	"%s"
	"%s/internal/config"
)

func main() {
	cfg := ztatic.MustLoadConfig[config.AppConfig]()
	app := ztatic.NewSecure()

	// Mount assets: in development, use os.DirFS with live reload; in production, use root DistFS embed
	isDev := ztatic.ActiveProfile().IsDevelopment()
	if isDev {
		fullstack.MountAssets(app.Echo, os.DirFS("dist"), true)
	} else if distSub, err := fs.Sub(%s.DistFS, "dist"); err == nil {
		fullstack.MountAssets(app.Echo, distSub, false)
	} else {
		fullstack.MountAssets(app.Echo, os.DirFS("dist"), false)
	}
	
	app.GET("/", func(c *ztatic.Context) error {
		return c.String(200, "Welcome to "+cfg.AppName+"!")
	})

	log.Info("Ztatic application starting", "app", cfg.AppName, "port", cfg.Port)
	if err := app.Start(":" + cfg.Port); err != nil {
		log.Error("server stopped", "error", err)
	}
}
`, moduleName, moduleName, moduleName)
		if err := os.WriteFile(filepath.Join(baseDir, "cmd/server", "main.go"), []byte(mainContent), 0644); err != nil {
			fmt.Printf("Error writing main.go: %v\n", err)
		}

		// Generate tools.go to pre-wire and lock generator and framework runtime dependencies
		toolsContent := `//go:build tools

package main

import (
	_ "github.com/a-h/templ"
	_ "ztatic-go-framework/config"
	_ "ztatic-go-framework/data"
	_ "ztatic-go-framework/realtime"
)
`
		if err := os.WriteFile(filepath.Join(baseDir, "tools.go"), []byte(toolsContent), 0644); err != nil {
			fmt.Printf("Error writing tools.go: %v\n", err)
		}

		// Locate framework root to seed go.sum and configure replace directive
		var frameworkDir string
		var frameworkSumData []byte

		if envDir := os.Getenv("ZTATIC_FRAMEWORK_DIR"); envDir != "" {
			if abs, err := filepath.Abs(envDir); err == nil {
				frameworkDir = abs
			}
		}

		if frameworkDir == "" {
			if cwd, err := os.Getwd(); err == nil {
				if modBytes, err := os.ReadFile(filepath.Join(cwd, "go.mod")); err == nil {
					if strings.Contains(string(modBytes), "module ztatic-go-framework") {
						frameworkDir = cwd
					}
				}
			}
		}

		if frameworkDir == "" {
			for _, rel := range []string{".", "..", "../.."} {
				if modBytes, err := os.ReadFile(filepath.Join(rel, "go.mod")); err == nil {
					if strings.Contains(string(modBytes), "module ztatic-go-framework") {
						if abs, err := filepath.Abs(rel); err == nil {
							frameworkDir = abs
							break
						}
					}
				}
			}
		}

		if frameworkDir != "" {
			frameworkSumData, _ = os.ReadFile(filepath.Join(frameworkDir, "go.sum"))
		} else {
			for _, sumPath := range []string{"go.sum", "../go.sum", filepath.Join(baseDir, "../go.sum")} {
				if data, err := os.ReadFile(sumPath); err == nil && len(data) > 0 {
					frameworkSumData = data
					break
				}
			}
		}

		// Pre-seed go.sum before running go mod tidy for offline/air-gapped stability
		if len(frameworkSumData) > 0 {
			if err := os.WriteFile(filepath.Join(baseDir, "go.sum"), frameworkSumData, 0644); err != nil {
				fmt.Printf("Warning: failed to seed go.sum: %v\n", err)
			}
		}

		replacePath := "../"
		if frameworkDir != "" {
			if rel, err := filepath.Rel(absBaseDir, frameworkDir); err == nil {
				replacePath = filepath.ToSlash(rel)
			}
		}

		// Generate go.mod
		modContent := fmt.Sprintf("module %s\n\ngo 1.21\n\nrequire (\n\tgithub.com/a-h/templ v0.3.1020\n\tztatic-go-framework v0.0.0\n)\n\nreplace ztatic-go-framework => %s\n", moduleName, replacePath)
		if frameworkDir != "" {
			if _, err := os.Stat(filepath.Join(frameworkDir, "echo")); err == nil {
				modContent += fmt.Sprintf("\nreplace github.com/labstack/echo/v5 => %s/echo\n", replacePath)
			}
		}
		if err := os.WriteFile(filepath.Join(baseDir, "go.mod"), []byte(modContent), 0644); err != nil {
			fmt.Printf("Error writing go.mod: %v\n", err)
		}

		// Run go mod tidy — pipe output so the developer can see what happens
		cmdTidy := exec.Command("go", "mod", "tidy")
		cmdTidy.Dir = baseDir
		cmdTidy.Stdout = os.Stdout
		cmdTidy.Stderr = os.Stderr
		if err := cmdTidy.Run(); err != nil {
			fmt.Printf("⚠️  'go mod tidy' failed: %v\n", err)
			fmt.Println("   Tip: In air-gapped/offline environments, run: GOSUMDB=off go mod tidy")
		}

		fmt.Println("✅ Project scaffolded successfully!")
		fmt.Printf("Next steps:\n  cd %s\n  ztatic dev\n", absBaseDir)
	},
}

func init() {
	newCmd.Flags().StringVarP(&newDir, "dir", "d", ".", "Base target directory for project scaffolding")
	rootCmd.AddCommand(newCmd)
}
