package main

import (
	"log/slog"
	"net/http"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework"
)

func main() {
	// Initialize the Ztatic Framework with Zero-Trust Security-by-Default
	// This automatically wires WAF, Strict Headers, CSRF, and Rate Limiting.
	app := ztatic.NewSecure()

	// Add a simple route
	app.GET("/", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"message": "Welcome to the secure Ztatic framework!",
			"status":  "secure",
		})
	})

	// Start the server
	slog.Info("Starting Ztatic Engine on :8080...")
	if err := app.Start(":8080"); err != nil {
		slog.Error("server crashed", "error", err)
	}
}
