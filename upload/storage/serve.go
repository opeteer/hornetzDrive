package storage

import (
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/errors"
)

// ServeConfig specifies response options when serving a file over HTTP.
type ServeConfig struct {
	Inline       bool
	Filename     string
	CacheControl string
	CustomCSP    string
}

// ServeOption configures file serving behaviors.
type ServeOption func(*ServeConfig)

// WithInline instructs the browser to attempt rendering the file inline (e.g. images, audio, video).
func WithInline() ServeOption {
	return func(cfg *ServeConfig) {
		cfg.Inline = true
	}
}

// WithDownload forces the browser to prompt a file download dialog (Content-Disposition: attachment).
func WithDownload() ServeOption {
	return func(cfg *ServeConfig) {
		cfg.Inline = false
	}
}

// WithFilename overrides the download filename sent in the Content-Disposition header.
func WithFilename(name string) ServeOption {
	return func(cfg *ServeConfig) {
		cfg.Filename = name
	}
}

// WithCacheMaxAge sets the Cache-Control max-age header.
func WithCacheMaxAge(d time.Duration) ServeOption {
	return func(cfg *ServeConfig) {
		cfg.CacheControl = fmt.Sprintf("public, max-age=%d, immutable", int(d.Seconds()))
	}
}

// ServeHTTP securely serves a stored file to the HTTP client with Range request support,
// zero-trust nosniff headers, and sandboxed CSP for inline SVGs/HTML.
func ServeHTTP(c *echo.Context, store Storage, key string, opts ...ServeOption) error {
	cfg := ServeConfig{
		Inline:       false,
		CacheControl: "public, max-age=86400", // 24h default cache
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	ctx := c.Request().Context()
	reader, record, err := store.Open(ctx, key)
	if err != nil {
		if errors.Is(err, ErrFileNotFound) {
			return errors.NotFound("File not found")
		}
		if errors.Is(err, ErrPathTraversal) {
			return errors.Forbidden("Access denied")
		}
		return errors.Internal("Failed to open file").WithInternal(err)
	}
	defer reader.Close()

	res := c.Response()
	header := res.Header()

	// 1. Zero-Trust nosniff enforcement
	header.Set("X-Content-Type-Options", "nosniff")

	// 2. Resolve Content-Type
	contentType := record.MIME
	if contentType == "" {
		contentType = mime.TypeByExtension(filepath.Ext(key))
		if contentType == "" {
			contentType = "application/octet-stream"
		}
	}
	header.Set("Content-Type", contentType)

	// 3. Resolve Filename for Content-Disposition
	downloadName := cfg.Filename
	if downloadName == "" {
		downloadName = record.OriginalName
	}
	if downloadName == "" {
		downloadName = filepath.Base(key)
	}
	// Sanitize quotes in filename
	downloadName = strings.ReplaceAll(downloadName, `"`, `_`)

	// 4. Content-Disposition and Sandboxed CSP
	if cfg.Inline {
		header.Set("Content-Disposition", fmt.Sprintf(`inline; filename="%s"`, downloadName))
		// If serving SVG or HTML inline, strictly sandbox JavaScript execution to prevent stored XSS
		if strings.Contains(contentType, "svg") || strings.Contains(contentType, "html") || strings.Contains(contentType, "xml") {
			csp := cfg.CustomCSP
			if csp == "" {
				csp = "default-src 'none'; sandbox"
			}
			header.Set("Content-Security-Policy", csp)
		}
	} else {
		header.Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, downloadName))
	}

	// 5. Caching and ETag
	if cfg.CacheControl != "" {
		header.Set("Cache-Control", cfg.CacheControl)
	}
	if record.SHA256 != "" {
		header.Set("ETag", fmt.Sprintf(`"%s"`, record.SHA256))
	}

	// 6. Serve with HTTP 206 Range Request support
	modTime := record.CreatedAt
	if modTime.IsZero() {
		modTime = time.Now().UTC()
	}

	http.ServeContent(res, c.Request(), downloadName, modTime, reader)
	return nil
}
