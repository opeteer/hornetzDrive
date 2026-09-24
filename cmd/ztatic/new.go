package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// runNew scaffolds a fresh Ztatic project architecture.
func runNew(args []string) {
	if len(args) < 1 {
		fmt.Println("Error: Project name required.")
		fmt.Println("Example: ztatic new myapp")
		os.Exit(1)
	}

	projectName := args[0]
	fmt.Printf("🚀 Scaffolding new Ztatic project: %s\n", projectName)

	// Define the standard architectural directory structure
	dirs := []string{
		"cmd/server",
		"internal/controllers",
		"internal/models",
		"internal/repositories",
		"internal/views/layouts",
		"internal/views/components",
		"assets/css",
		"assets/js",
		"db/migrations",
	}

	// Create directories
	for _, dir := range dirs {
		path := filepath.Join(projectName, dir)
		if err := os.MkdirAll(path, 0755); err != nil {
			fmt.Printf("Error creating directory %s: %v\n", path, err)
			os.Exit(1)
		}
	}

	// Generate main.go stub
	mainContent := `package main

import (
	"log"
	"ztatic-go-framework"
)

func main() {
	app := ztatic.NewSecure()
	
	app.GET("/", func(c ztatic.Context) error {
		return c.String(200, "Welcome to Ztatic!")
	})

	log.Fatal(app.Start(":8080"))
}
`
	if err := os.WriteFile(filepath.Join(projectName, "cmd/server", "main.go"), []byte(mainContent), 0644); err != nil {
		fmt.Printf("Error writing main.go: %v\n", err)
	}

	// Generate go.mod
	modContent := fmt.Sprintf("module %s\n\ngo 1.21\n", projectName)
	if err := os.WriteFile(filepath.Join(projectName, "go.mod"), []byte(modContent), 0644); err != nil {
		fmt.Printf("Error writing go.mod: %v\n", err)
	}

	fmt.Println("✅ Project scaffolded successfully!")
	fmt.Printf("Next steps:\n  cd %s\n  ztatic dev\n", projectName)
}
