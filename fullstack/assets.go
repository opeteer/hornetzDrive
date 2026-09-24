package fullstack

import (
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// DefaultAssetManager is the global asset manager instance used by the AssetURL helper.
var DefaultAssetManager *AssetManager

// AssetManager seamlessly bridges Development (live reload, un-hashed) and
// Production (embed.FS, hashed, immutable) static asset serving.
type AssetManager struct {
	fs          fs.FS
	isDev       bool
	urlPrefix   string
	manifest    Manifest
	startupTime int64
}

// NewAssetManager initializes a dual-mode asset engine.
// In Development (isDev=true), it serves directly from os.DirFS to support live reloading.
// In Production (isDev=false), it serves from the provided embedFS and uses the manifest for cache-busting.
func NewAssetManager(fileSystem fs.FS, isDev bool, urlPrefix string) (*AssetManager, error) {
	am := &AssetManager{
		fs:          fileSystem,
		isDev:       isDev,
		urlPrefix:   strings.TrimSuffix(urlPrefix, "/"),
		manifest:    make(Manifest),
		startupTime: time.Now().Unix(),
	}

	if !isDev {
		// In production, attempt to load manifest.json from the embedded filesystem
		manifest, err := LoadManifest(fileSystem, "manifest.json")
		if err == nil {
			am.manifest = manifest
		}
	}

	DefaultAssetManager = am
	return am, nil
}

// Mount attaches the AssetManager to the Echo application engine.
func (am *AssetManager) Mount(e *echo.Echo) {
	// Serve static files with intelligent cache headers
	fileServer := http.FileServer(http.FS(am.fs))

	e.GET(am.urlPrefix+"/*", func(c *echo.Context) error {
		req := c.Request()
		res := c.Response()

		// Strip prefix to find file in FS
		req.URL.Path = strings.TrimPrefix(req.URL.Path, am.urlPrefix)

		if am.isDev {
			// Development: Never cache, always revalidate for instant live reload
			res.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		} else {
			// Production: Aggressive immutable caching for content-hashed assets (1 year)
			res.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}

		fileServer.ServeHTTP(res, req)
		return nil
	})
}

// GetURL resolves the correct URL path for an asset.
// In Development: Appends a startup timestamp to bust cache (`/static/css/app.css?v=1695500000`)
// In Production: Looks up the content-hashed filename from manifest (`/static/css/app.a8f9b2.css`)
func (am *AssetManager) GetURL(assetPath string) string {
	if am.isDev {
		return fmt.Sprintf("%s/%s?v=%d", am.urlPrefix, assetPath, am.startupTime)
	}

	// Look up hashed name in manifest
	if hashedName, ok := am.manifest[assetPath]; ok {
		return fmt.Sprintf("%s/%s", am.urlPrefix, hashedName)
	}

	// Fallback to original name if manifest fails
	return fmt.Sprintf("%s/%s", am.urlPrefix, assetPath)
}

// AssetURL is a global helper function designed to be called directly from
// Templ view components. E.g. <link rel="stylesheet" href={ fullstack.AssetURL("css/app.css") } />
func AssetURL(assetPath string) string {
	if DefaultAssetManager == nil {
		// Fallback if AssetManager was not initialized
		return "/static/" + assetPath
	}
	return DefaultAssetManager.GetURL(assetPath)
}

// MountAssets is a convenience builder for wiring the asset manager quickly.
func MountAssets(e *echo.Echo, dirPath string, isDev bool) error {
	var fileSystem fs.FS
	if isDev {
		fileSystem = os.DirFS(dirPath)
	} else {
		// In a real application, you would pass your //go:embed fs.FS here
		fileSystem = os.DirFS(dirPath) // Fallback for demonstration
	}

	am, err := NewAssetManager(fileSystem, isDev, "/static")
	if err != nil {
		return err
	}
	am.Mount(e)
	return nil
}
