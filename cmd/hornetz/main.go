package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"ztatic-go-framework"
	"ztatic-go-framework/data"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/controllers"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/download"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/ui/components"
	"ztatic-go-framework/internal/upload"
	"ztatic-go-framework/log"
	"ztatic-go-framework/realtime"
	"ztatic-go-framework/security/web"
	frameworkUpload "ztatic-go-framework/upload"
)

// AppConfig defines the type-safe environment configuration schema for Hornetz Drive.
type AppConfig struct {
	Port         string `env:"PORT" envDefault:"8071"`
	DBDriver     string `env:"DB_DRIVER" envDefault:"sqlite3"`
	DBDSN        string `env:"DB_DSN" envDefault:"file:hornetz.db?cache=shared&mode=rwc&_journal_mode=WAL&_foreign_keys=on"`
	CASDir       string `env:"CAS_DIR" envDefault:"storage/cas"`
	TmpDir       string `env:"TMP_DIR" envDefault:"storage/tmp"`
	StorageQuota int64  `env:"STORAGE_QUOTA" envDefault:"0"`
	StorageKey   string `env:"STORAGE_MASTER_KEY" envDefault:""`
}

func main() {
	appCfg, err := ztatic.LoadConfig[AppConfig]()
	if err != nil {
		appCfg = &AppConfig{
			Port:         "8071",
			DBDriver:     "sqlite3",
			DBDSN:        "file:hornetz.db?cache=shared&mode=rwc&_journal_mode=WAL&_foreign_keys=on",
			CASDir:       "storage/cas",
			TmpDir:       "storage/tmp",
			StorageQuota: 0,
		}
	}

	cfg := ztatic.DefaultConfig()
	// Disable automatic per-request nonce injection so browsers respect 'unsafe-inline' for Alpine.js store scripts
	cfg.Security.Headers.EnableCSPNonce = false
	// Set hardened Content-Security-Policy with default-src 'self' while allowing required frontend CDNs and same-origin preview framing
	cfg.Security.Headers.ContentSecurityPolicy = "default-src 'self'; frame-src 'self' blob:; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https://cdn.tailwindcss.com https://cdn.skypack.dev https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' data: https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' blob:; worker-src 'self' blob:; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self';"
	// Allow client-side JavaScript (Alpine.js) to read _csrf cookie with SameSite protection
	cfg.Security.CSRF.CookieHTTPOnly = false
	cfg.Security.CSRF.CookieSameSite = http.SameSiteLaxMode
	cfg.Security.CSRF.Skipper = func(c *echo.Context) bool {
		path := c.Request().URL.Path
		return path == "/docs" || strings.HasPrefix(path, "/docs/")
	}
	// Allow chunk uploads up to 50MB
	cfg.Security.WAF.MaxBodySize = 50 * 1024 * 1024

	app := ztatic.NewWithConfig(cfg)
	app.Echo.IPExtractor = echo.ExtractIPFromXFFHeader(echo.TrustLoopback(true), echo.TrustLinkLocal(true))

	// High-performance HTTP response compression (Gzip) with intelligent binary stream bypass
	app.Echo.Use(middleware.GzipWithConfig(middleware.GzipConfig{
		Level:     5,
		MinLength: 1024,
		Skipper: func(c *echo.Context) bool {
			p := c.Request().URL.Path
			// Skip streaming file downloads, chunk uploads, and SSE streams
			if strings.HasSuffix(p, "/download") || strings.HasPrefix(p, "/upload") || p == "/sse" {
				return true
			}
			return false
		},
	}))

	dbEngine, err := data.NewDBEngine(appCfg.DBDriver, appCfg.DBDSN)
	if err != nil {
		log.Error("Failed to initialize DB", "error", err)
		return
	}
	defer dbEngine.Close()

	auth.SetDB(dbEngine)
	_, _ = crypto.InitStandardStorageKey(appCfg.StorageKey, "storage")

	migrationEngine := data.NewMigrationEngine(dbEngine.SQL)
	migDir := "data/migrations_sqlite3"
	if appCfg.DBDriver == "postgres" {
		migDir = "data/migrations_postgres"
	}
	if err := migrationEngine.RunMigrations(ztatic.MigrationFS, migDir, appCfg.DBDriver); err != nil {
		log.Error("Failed to run migrations", "error", err)
		return
	}

	broker := realtime.NewMemoryBroker()
	sseAuthorizer := func(c *echo.Context, topic string) bool {
		userID := auth.GetUserID(c)
		if strings.HasPrefix(topic, "nest:user_") {
			return topic == fmt.Sprintf("nest:user_%d", userID)
		}
		return true
	}
	app.GET("/sse", realtime.AuthorizedSSEHandler(broker, sseAuthorizer), auth.RequireAuth(dbEngine))

	// Mount Static Assets from embedded FS
	assetMgr, err := fullstack.NewAssetManager(ztatic.AssetsFS, false, "/assets")
	if err != nil {
		log.Error("Failed to init asset manager", "error", err)
		return
	}
	assetMgr.Mount(app.Echo)

	casEngine, err := storage.NewCASEngine(appCfg.CASDir)
	if err != nil {
		log.Error("Failed to init CAS Engine", "error", err)
		return
	}

	sessionMgr, err := upload.NewSessionManager(appCfg.TmpDir)
	if err != nil {
		log.Error("Failed to init Session Manager", "error", err)
		return
	}

	fileCtrl := &controllers.FileController{
		DB:         dbEngine,
		CAS:        casEngine,
		QuotaBytes: appCfg.StorageQuota,
	}
	fileCtrl.SeedInitialData()

	downloadMgr, err := download.NewDownloadManager(casEngine, dbEngine, broker, appCfg.TmpDir, appCfg.StorageQuota)
	if err != nil {
		log.Error("Failed to init Download Manager", "error", err)
		return
	}

	downloadCtrl := &controllers.DownloadController{
		Manager: downloadMgr,
		DB:      dbEngine,
		CAS:     casEngine,
	}

	apiGroup := app.Group("/api", auth.RequireAuth(dbEngine))
	apiGroup.GET("/files", fileCtrl.GetFiles)
	apiGroup.PATCH("/files/:id", fileCtrl.RenameFile)
	apiGroup.PATCH("/files/:id/move", fileCtrl.MoveFile)
	apiGroup.POST("/files/move-batch", fileCtrl.MoveFilesBatch)
	apiGroup.GET("/folders", fileCtrl.GetFolders)
	apiGroup.POST("/folders", fileCtrl.CreateFolder)
	apiGroup.DELETE("/folders/:id", fileCtrl.DeleteFolder)
	apiGroup.PATCH("/folders/:id", fileCtrl.RenameFolder)
	apiGroup.GET("/storage/stats", fileCtrl.GetStorageStats)
	apiGroup.GET("/files/:id/download", fileCtrl.DownloadFile)
	apiGroup.HEAD("/files/:id/download", fileCtrl.DownloadFile)
	apiGroup.GET("/files/:id/preview", fileCtrl.PreviewFile)
	apiGroup.HEAD("/files/:id/preview", fileCtrl.PreviewFile)
	apiGroup.GET("/files/:id/thumbnail", fileCtrl.ThumbnailFile)
	apiGroup.DELETE("/files/trash/empty", fileCtrl.EmptyTrash)
	apiGroup.DELETE("/files/:id", fileCtrl.DeleteFile)
	apiGroup.POST("/files/:id/restore", fileCtrl.RestoreFile)
	apiGroup.POST("/files/:id/star", fileCtrl.StarFile)
	apiGroup.POST("/vault/lock", auth.LockVault)

	apiGroup.GET("/downloads", downloadCtrl.ListDownloads)
	apiGroup.POST("/downloads", downloadCtrl.StartDownload)
	apiGroup.POST("/downloads/batch", downloadCtrl.StartBatchDownload)
	apiGroup.GET("/downloads/:id", downloadCtrl.GetDownloadStatus)
	apiGroup.DELETE("/downloads/:id", downloadCtrl.CancelDownload)
	apiGroup.DELETE("/downloads/:id/dismiss", downloadCtrl.DismissDownload)
	apiGroup.POST("/downloads/parse", downloadCtrl.ParseLink)

	reconcileCtrl := &controllers.ReconcileController{
		DB:         dbEngine,
		SessionMgr: sessionMgr,
		CAS:        casEngine,
		FileCtrl:   fileCtrl,
		QuotaBytes: appCfg.StorageQuota,
	}
	apiGroup.POST("/reconcile/tree-diff", reconcileCtrl.DiffTree)

	uploadCtrl := &controllers.UploadController{
		SessionMgr: sessionMgr,
		CAS:        casEngine,
		Broker:     broker,
		DB:         dbEngine,
		FileCtrl:   fileCtrl,
		QuotaBytes: appCfg.StorageQuota,
	}

	// Phase 3: Security & Shuffler
	secCtrl := &controllers.SecurityController{
		CAS:        casEngine,
		Broker:     broker,
		DB:         dbEngine,
		TmpDir:     appCfg.TmpDir,
		SessionMgr:  sessionMgr,
		UploadCtrl:  uploadCtrl,
		DownloadMgr: downloadMgr,
	}
	app.POST("/api/purge", secCtrl.PanicPurge, web.AdaptiveRateLimiterWithConfig(web.AuthRateLimiterConfig()))

	shuffler := &storage.ChitinShuffler{CAS: casEngine}
	shuffler.StartBackgroundWorker(context.Background(), 6*time.Hour)

	// Background reaper worker for stale upload sessions, temp files, and expired vault keys
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			sessionMgr.CleanupStaleSessions(24 * time.Hour)
			auth.GlobalSessionStore.CleanupStaleKeys()
			uploadCtrl.PruneCompletedSessions(5 * time.Minute)
			downloadMgr.PruneOldTasks(1 * time.Hour)
		}
	}()

	app.POST("/login", auth.LoginMock, web.AdaptiveRateLimiterWithConfig(web.AuthRateLimiterConfig()))

	// Protected Upload Routes with RouteLimit
	uploadGroup := app.Group("/upload", auth.RequireAuth(dbEngine), auth.VaultKeyMiddleware(), frameworkUpload.RouteLimit(50*1024*1024))
	uploadGroup.POST("/init", uploadCtrl.InitSession)
	uploadGroup.POST("/verify-pow", uploadCtrl.VerifyProofOfOwnership)
	uploadGroup.PUT("/:session_id", uploadCtrl.UploadChunk)
	uploadGroup.GET("/:session_id", uploadCtrl.GetStatus)
	uploadGroup.DELETE("/:session_id", uploadCtrl.AbortSession)

	// Landing Page route
	app.GET("/", func(c *echo.Context) error {
		return components.LandingPage(c).Render(c.Request().Context(), c.Response())
	}, auth.EnsureDashboardSessionMiddleware())

	// Storage Web Application Dashboard routes
	app.GET("/app", func(c *echo.Context) error {
		return components.Dashboard(c).Render(c.Request().Context(), c.Response())
	}, auth.EnsureDashboardSessionMiddleware())
	app.GET("/drive", func(c *echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/app")
	})
	app.GET("/dashboard", func(c *echo.Context) error {
		return c.Redirect(http.StatusMovedPermanently, "/app")
	})

	log.Info("Starting Hornetz Drive", "port", appCfg.Port, "driver", appCfg.DBDriver)
	if err := app.Start(":" + appCfg.Port); err != nil {
		log.Error("Server stopped", "error", err)
	}
}
