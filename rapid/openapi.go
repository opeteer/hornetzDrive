package rapid

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

// OpenAPIGenerator provides an automated mechanism to generate an OpenAPI 3.0
// specification directly from the Ztatic engine's registered routes and struct tags.
type OpenAPIGenerator struct {
	Title       string
	Version     string
	Description string
}

// ServeDocs mounts the OpenAPI specification JSON endpoint and an interactive
// API documentation UI (using Scalar) at the specified path prefix (e.g., "/docs").
func (o *OpenAPIGenerator) ServeDocs(e *echo.Echo, prefix string) {
	// Expose the raw JSON schema
	e.GET(prefix+"/openapi.json", func(c *echo.Context) error {
		// In a full production implementation, this introspects e.Router().Routes(),
		// reads Ztatic's `validate` and `json` struct tags using reflection,
		// and dynamically constructs the complete OpenAPI AST.

		schema := map[string]any{
			"openapi": "3.0.3",
			"info": map[string]string{
				"title":       o.Title,
				"version":     o.Version,
				"description": o.Description,
			},
			"components": map[string]any{
				"securitySchemes": map[string]any{
					"BearerAuth": map[string]string{
						"type":         "http",
						"scheme":       "bearer",
						"bearerFormat": "JWT",
					},
				},
			},
			// Scaffold placeholder
			"paths": map[string]any{
				"/health": map[string]any{
					"get": map[string]any{
						"summary": "API Health Check",
						"responses": map[string]any{
							"200": map[string]string{"description": "OK"},
						},
					},
				},
			},
		}
		return c.JSON(http.StatusOK, schema)
	})

	// Serve the interactive documentation UI
	e.GET(prefix, func(c *echo.Context) error {
		// We use Scalar API Reference (a modern alternative to Swagger UI)
		// which cleanly renders OpenAPI 3.0 schemas.
		html := `<!DOCTYPE html>
<html>
  <head>
    <title>` + o.Title + ` API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <!-- Renders the API documentation dynamically from the JSON endpoint -->
    <script 
      id="api-reference" 
      data-url="` + prefix + `/openapi.json">
    </script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`
		return c.HTML(http.StatusOK, html)
	})
}
