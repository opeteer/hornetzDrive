package main

import (
	"context"
	"time"

	"github.com/labstack/echo/v5"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"

	"ztatic-go-framework"
	"ztatic-go-framework/data"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/controllers"
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
	Port     string `env:"PORT" envDefault:"8071"`
	DBDriver string `env:"DB_DRIVER" envDefault:"sqlite3"`
	DBDSN    string `env:"DB_DSN" envDefault:"file:hornetz.db?cache=shared&mode=rwc&_journal_mode=WAL&_foreign_keys=on"`
	CASDir   string `env:"CAS_DIR" envDefault:"storage/cas"`
	TmpDir   string `env:"TMP_DIR" envDefault:"storage/tmp"`
}

func main() {
	appCfg, err := ztatic.LoadConfig[AppConfig]()
	if err != nil {
		appCfg = &AppConfig{
			Port:     "8071",
			DBDriver: "sqlite3",
			DBDSN:    "file:hornetz.db?cache=shared&mode=rwc&_journal_mode=WAL&_foreign_keys=on",
			CASDir:   "storage/cas",
			TmpDir:   "storage/tmp",
		}
	}

	cfg := ztatic.DefaultConfig()
	// Disable automatic per-request nonce injection so browsers respect 'unsafe-inline' for Alpine.js store scripts
	cfg.Security.Headers.EnableCSPNonce = false
	// Set Content-Security-Policy to allow Tailwind, Turbo, Alpine.js, and Google Fonts CDNs cleanly
	cfg.Security.Headers.ContentSecurityPolicy = "default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; font-src * data: https://fonts.gstatic.com; style-src * 'unsafe-inline' https://fonts.googleapis.com; script-src * 'unsafe-inline' 'unsafe-eval' blob: https://cdn.tailwindcss.com https://cdn.skypack.dev https://cdn.jsdelivr.net;"
	// Allow client-side JavaScript (Alpine.js) to read _csrf cookie
	cfg.Security.CSRF.CookieHTTPOnly = false
	// Allow chunk uploads up to 50MB
	cfg.Security.WAF.MaxBodySize = 50 * 1024 * 1024

	app := ztatic.NewWithConfig(cfg)
	app.Echo.IPExtractor = echo.ExtractIPFromXFFHeader(echo.TrustLoopback(true), echo.TrustLinkLocal(true))

	dbEngine, err := data.NewDBEngine(appCfg.DBDriver, appCfg.DBDSN)
	if err != nil {
		log.Error("Failed to initialize DB", "error", err)
		return
	}
	defer dbEngine.Close()

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
	app.GET("/sse", realtime.SSEHandler(broker))

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
		DB:  dbEngine,
		CAS: casEngine,
	}
	fileCtrl.SeedInitialData()

	app.GET("/api/files", fileCtrl.GetFiles)
	app.GET("/api/folders", fileCtrl.GetFolders)
	app.POST("/api/folders", fileCtrl.CreateFolder)
	app.DELETE("/api/folders/:id", fileCtrl.DeleteFolder)
	app.PATCH("/api/folders/:id", fileCtrl.RenameFolder)
	app.GET("/api/storage/stats", fileCtrl.GetStorageStats)
	app.GET("/api/files/:id/download", fileCtrl.DownloadFile)
	app.DELETE("/api/files/trash/empty", fileCtrl.EmptyTrash)
	app.DELETE("/api/files/:id", fileCtrl.DeleteFile)
	app.POST("/api/files/:id/restore", fileCtrl.RestoreFile)
	app.POST("/api/files/:id/star", fileCtrl.StarFile)
	app.POST("/api/vault/lock", auth.LockVault)

	uploadCtrl := &controllers.UploadController{
		SessionMgr: sessionMgr,
		CAS:        casEngine,
		Broker:     broker,
		DB:         dbEngine,
	}

	// Phase 3: Security & Shuffler
	secCtrl := &controllers.SecurityController{
		CAS:    casEngine,
		Broker: broker,
		DB:     dbEngine,
		TmpDir: appCfg.TmpDir,
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
		}
	}()

	app.POST("/login", auth.LoginMock, web.AdaptiveRateLimiterWithConfig(web.AuthRateLimiterConfig()))

	// Protected Upload Routes with RouteLimit
	uploadGroup := app.Group("/upload", auth.VaultKeyMiddleware(), frameworkUpload.RouteLimit(50*1024*1024))
	uploadGroup.POST("/init", uploadCtrl.InitSession)
	uploadGroup.PUT("/:session_id", uploadCtrl.UploadChunk)
	uploadGroup.GET("/:session_id", uploadCtrl.GetStatus)
	uploadGroup.DELETE("/:session_id", uploadCtrl.AbortSession)

	app.GET("/", func(c *echo.Context) error {
		return components.Dashboard(c).Render(c.Request().Context(), c.Response())
	})

	log.Info("Starting Hornetz Drive", "port", appCfg.Port, "driver", appCfg.DBDriver)
	if err := app.Start(":" + appCfg.Port); err != nil {
		log.Error("Server stopped", "error", err)
	}
}
