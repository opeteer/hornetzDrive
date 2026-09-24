package main

import (
	"fmt"
	"os"
)

// In a non-sandbox environment, this would heavily utilize "github.com/spf13/cobra"
// to manage nested commands, flags, and help menus.

// Ztatic CLI Entrypoint
func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "new":
		runNew(os.Args[2:])
	case "dev":
		runDev(os.Args[2:])
	case "build":
		runBuild(os.Args[2:])
	default:
		fmt.Printf("Error: Unknown command '%s'\n\n", command)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println("⚡ Ztatic CLI - The Security-First Full-Stack Go Framework")
	fmt.Println("\nUsage:")
	fmt.Println("  ztatic <command> [arguments]")
	fmt.Println("\nCommands:")
	fmt.Println("  new <name>   Scaffold a new Ztatic project architecture")
	fmt.Println("  dev          Start the live-reloading development server")
	fmt.Println("  build        Compile assets and build the optimized production binary")
}
