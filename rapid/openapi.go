package rapid

import (
	"html"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/labstack/echo/v5"
)

// DefaultOpenAPIGenerator provides a globally accessible generator for DX.
var DefaultOpenAPIGenerator = NewOpenAPIGenerator()

// RouteMetadata holds OpenAPI metadata for a specific route.
type RouteMetadata struct {
	Summary      string
	Description  string
	Tags         []string
	RequestType  reflect.Type
	ResponseType reflect.Type
	Security     []string
}

// OpenAPIGenerator builds OpenAPI 3.0 specs dynamically.
type OpenAPIGenerator struct {
	Title       string
	Version     string
	Description string
	ServerURL   string
	routes      map[string]RouteMetadata
	mu          sync.RWMutex
}

// NewOpenAPIGenerator initializes a new OpenAPI generator.
func NewOpenAPIGenerator() *OpenAPIGenerator {
	return &OpenAPIGenerator{
		Title:       "Ztatic API",
		Version:     "1.0.0",
		Description: "Auto-generated OpenAPI 3.0 documentation",
		routes:      make(map[string]RouteMetadata),
	}
}

// RegisterRouteMeta registers OpenAPI metadata for a route.
func (o *OpenAPIGenerator) RegisterRouteMeta(method, path string, meta RouteMetadata) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.routes[method+" "+path] = meta
}

// ServeDocs mounts the OpenAPI specification JSON endpoint and an interactive 
// API documentation UI (using Scalar) at the specified path prefix (e.g., "/docs").
func (o *OpenAPIGenerator) ServeDocs(e *echo.Echo, prefix string) {
	// Expose the raw JSON schema
	e.GET(prefix+"/openapi.json", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, o.BuildOpenAPI(e))
	})

	// Serve the interactive documentation UI
	e.GET(prefix, func(c *echo.Context) error {
		escapedTitle := html.EscapeString(o.Title)
		nonceAttr := ""
		if nonce, ok := c.Get("csp_nonce").(string); ok && nonce != "" {
			nonceAttr = ` nonce="` + nonce + `"`
		}
		html := `<!DOCTYPE html>
<html>
  <head>
    <title>` + escapedTitle + ` API Reference</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
  </head>
  <body>
    <!-- Renders the API documentation dynamically from the JSON endpoint -->
    <script` + nonceAttr + ` 
      id="api-reference" 
      data-url="` + prefix + `/openapi.json">
    </script>
    <script` + nonceAttr + ` src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>`
		return c.HTML(http.StatusOK, html)
	})
}

// BuildOpenAPI dynamically constructs the OpenAPI AST based on registered Echo routes.
func (o *OpenAPIGenerator) BuildOpenAPI(e *echo.Echo) map[string]any {
	o.mu.RLock()
	defer o.mu.RUnlock()

	schemas := make(map[string]any)
	paths := make(map[string]any)

	for _, route := range e.Router().Routes() {
		// Filter out internal and doc endpoints
		if strings.HasSuffix(route.Path, "openapi.json") || strings.HasSuffix(route.Path, "/docs") || route.Path == "" || route.Path == "/*" {
			continue
		}

		pathKey := normalizePath(route.Path)
		methodLower := strings.ToLower(route.Method)

		if paths[pathKey] == nil {
			paths[pathKey] = make(map[string]any)
		}
		
		opMap := paths[pathKey].(map[string]any)

		// Parse Path Parameters
		var params []any
		for _, seg := range strings.Split(route.Path, "/") {
			if strings.HasPrefix(seg, ":") {
				paramName := strings.TrimPrefix(seg, ":")
				params = append(params, map[string]any{
					"name":     paramName,
					"in":       "path",
					"required": true,
					"schema":   map[string]any{"type": "string"},
				})
			}
		}

		op := map[string]any{
			"summary": route.Name,
			"responses": map[string]any{
				"200": map[string]any{"description": "OK"},
			},
		}

		if len(params) > 0 {
			op["parameters"] = params
		}

		// Inject explicit metadata if registered
		metaKey := route.Method + " " + route.Path
		if meta, ok := o.routes[metaKey]; ok {
			if meta.Summary != "" {
				op["summary"] = meta.Summary
			}
			if meta.Description != "" {
				op["description"] = meta.Description
			}
			if len(meta.Tags) > 0 {
				op["tags"] = meta.Tags
			}
			if len(meta.Security) > 0 {
				sec := []any{}
				for _, s := range meta.Security {
					sec = append(sec, map[string]any{s: []string{}})
				}
				op["security"] = sec
			}

			visited := make(map[reflect.Type]string)
			
			if meta.RequestType != nil && (route.Method == "POST" || route.Method == "PUT" || route.Method == "PATCH") {
				schemaRef, defs := buildSchemaFromType(meta.RequestType, visited)
				for k, v := range defs {
					schemas[k] = v
				}
				op["requestBody"] = map[string]any{
					"required": true,
					"content": map[string]any{
						"application/json": map[string]any{
							"schema": schemaRef,
						},
					},
				}
			}

			if meta.ResponseType != nil {
				schemaRef, defs := buildSchemaFromType(meta.ResponseType, visited)
				for k, v := range defs {
					schemas[k] = v
				}
				op["responses"] = map[string]any{
					"200": map[string]any{
						"description": "OK",
						"content": map[string]any{
							"application/json": map[string]any{
								"schema": schemaRef,
							},
						},
					},
				}
			}
		}
		
		opMap[methodLower] = op
	}

	schema := map[string]any{
		"openapi": "3.0.3",
		"info": map[string]string{
			"title":       o.Title,
			"version":     o.Version,
			"description": o.Description,
		},
		"components": map[string]any{
			"schemas": schemas,
			"securitySchemes": map[string]any{
				"BearerAuth": map[string]string{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
				"bearerAuth": map[string]string{
					"type":         "http",
					"scheme":       "bearer",
					"bearerFormat": "JWT",
				},
				"CookieAuth": map[string]string{
					"type": "apiKey",
					"in":   "cookie",
					"name": "ztatic_session",
				},
				"cookieAuth": map[string]string{
					"type": "apiKey",
					"in":   "cookie",
					"name": "ztatic_session",
				},
			},
		},
		"paths": paths,
	}

	if o.ServerURL != "" {
		schema["servers"] = []map[string]string{
			{"url": o.ServerURL},
		}
	}

	return schema
}

func normalizePath(path string) string {
	segs := strings.Split(path, "/")
	for i, seg := range segs {
		if strings.HasPrefix(seg, ":") {
			segs[i] = "{" + strings.TrimPrefix(seg, ":") + "}"
		}
	}
	return strings.Join(segs, "/")
}

// buildSchemaFromType uses reflection to generate OpenAPI schema objects from Go structs.
func buildSchemaFromType(t reflect.Type, visited map[reflect.Type]string) (schemaRef map[string]any, definitions map[string]any) {
	definitions = make(map[string]any)
	if t == nil {
		return map[string]any{}, definitions
	}

	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}

	// Handle standard Go time.Time
	if t.PkgPath() == "time" && t.Name() == "Time" {
		return map[string]any{"type": "string", "format": "date-time"}, definitions
	}

	if t.Name() != "" && t.Kind() == reflect.Struct {
		if ref, ok := visited[t]; ok {
			return map[string]any{"$ref": ref}, definitions
		}
		refPath := "#/components/schemas/" + t.Name()
		visited[t] = refPath
		
		schema := map[string]any{
			"type": "object",
		}
		props := make(map[string]any)
		var req []string

		for i := 0; i < t.NumField(); i++ {
			field := t.Field(i)
			
			// Flatten embedded anonymous structs
			if field.Anonymous {
				_, fieldDefs := buildSchemaFromType(field.Type, visited)
				for k, v := range fieldDefs {
					definitions[k] = v
				}
				
				// Extract the embedded struct type name, handling pointers
				embedType := field.Type
				for embedType.Kind() == reflect.Pointer {
					embedType = embedType.Elem()
				}
				
				// Merge properties and required fields into parent
				if embedDef, ok := fieldDefs[embedType.Name()].(map[string]any); ok {
					if embedProps, ok := embedDef["properties"].(map[string]any); ok {
						for k, v := range embedProps {
							props[k] = v
						}
					}
					if embedReq, ok := embedDef["required"].([]string); ok {
						req = append(req, embedReq...)
					}
				}
				continue
			}

			if !field.IsExported() {
				continue
			}
			
			jsonTag := field.Tag.Get("json")
			if jsonTag == "-" {
				continue
			}
			
			name := field.Name
			if jsonTag != "" {
				name = strings.Split(jsonTag, ",")[0]
			}

			fieldRef, fieldDefs := buildSchemaFromType(field.Type, visited)
			for k, v := range fieldDefs {
				definitions[k] = v
			}

			valTag := field.Tag.Get("validate")
			if strings.Contains(valTag, "required") {
				req = append(req, name)
			}
			
			// Map validation constraints
			if strings.Contains(valTag, "email") {
				fieldRef["format"] = "email"
			}
			if strings.Contains(valTag, "uuid") {
				fieldRef["format"] = "uuid"
			}
			if strings.Contains(valTag, "url") {
				fieldRef["format"] = "uri"
			}
			if strings.Contains(valTag, "phone") {
				fieldRef["format"] = "tel"
			}
			if strings.Contains(valTag, "strong_password") {
				fieldRef["format"] = "password"
			}
			if strings.Contains(valTag, "credit_card") {
				fieldRef["format"] = "credit-card"
			}
			if strings.Contains(valTag, "json") {
				fieldRef["contentMediaType"] = "application/json"
			}
			if strings.Contains(valTag, "slug") {
				fieldRef["pattern"] = "^[a-z0-9]+(?:-[a-z0-9]+)*$"
			}
			
			parts := strings.Split(valTag, ",")
			for _, p := range parts {
				if strings.HasPrefix(p, "min=") {
					if v, err := strconv.Atoi(strings.TrimPrefix(p, "min=")); err == nil {
						if field.Type.Kind() == reflect.String {
							fieldRef["minLength"] = v
						} else if field.Type.Kind() == reflect.Int || field.Type.Kind() == reflect.Int64 || field.Type.Kind() == reflect.Float64 {
							fieldRef["minimum"] = v
						}
					}
				}
				if strings.HasPrefix(p, "max=") {
					if v, err := strconv.Atoi(strings.TrimPrefix(p, "max=")); err == nil {
						if field.Type.Kind() == reflect.String {
							fieldRef["maxLength"] = v
						} else if field.Type.Kind() == reflect.Int || field.Type.Kind() == reflect.Int64 || field.Type.Kind() == reflect.Float64 {
							fieldRef["maximum"] = v
						}
					}
				}
			}

			props[name] = fieldRef
		}
		
		if len(props) > 0 {
			schema["properties"] = props
		}
		if len(req) > 0 {
			schema["required"] = req
		}

		definitions[t.Name()] = schema
		return map[string]any{"$ref": refPath}, definitions
	}

	switch t.Kind() {
	case reflect.String:
		return map[string]any{"type": "string"}, definitions
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return map[string]any{"type": "integer"}, definitions
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}, definitions
	case reflect.Bool:
		return map[string]any{"type": "boolean"}, definitions
	case reflect.Slice, reflect.Array:
		itemRef, itemDefs := buildSchemaFromType(t.Elem(), visited)
		for k, v := range itemDefs {
			definitions[k] = v
		}
		return map[string]any{"type": "array", "items": itemRef}, definitions
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": true}, definitions
	default:
		return map[string]any{"type": "string"}, definitions
	}
}
