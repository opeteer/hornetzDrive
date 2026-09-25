package main

import (
	"context"
	"log"
	"os"
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
	"ztatic-go-framework/realtime"
)

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	app := ztatic.NewSecure()
	app.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval' blob: data:; font-src * data:; style-src * 'unsafe-inline'; script-src * 'unsafe-inline' 'unsafe-eval' blob: https://cdn.tailwindcss.com https://cdn.skypack.dev https://cdn.jsdelivr.net;")
			return next(c)
		}
	})

	dbDriver := getEnv("DB_DRIVER", "sqlite3")
	dbDsn := getEnv("DB_DSN", "file:hornetz.db?cache=shared&mode=rwc&_journal_mode=WAL")
	port := getEnv("PORT", "8071")

	dbEngine, err := data.NewDBEngine(dbDriver, dbDsn)
	if err != nil {
		log.Fatalf("Failed to initialize DB: %v", err)
	}
	defer dbEngine.Close()

	migrationEngine := data.NewMigrationEngine(dbEngine.SQL)
	migDir := "data/migrations_sqlite3"
	if dbDriver == "postgres" {
		migDir = "data/migrations_postgres"
	}
	if err := migrationEngine.RunMigrations(ztatic.MigrationFS, migDir, dbDriver); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	broker := realtime.NewMemoryBroker()
	app.GET("/sse", realtime.SSEHandler(broker))

	// Mount Static Assets from embedded FS
	assetMgr, err := fullstack.NewAssetManager(ztatic.AssetsFS, false, "/assets")
	if err != nil {
		log.Fatalf("Failed to init asset manager: %v", err)
	}
	assetMgr.Mount(app.Echo)

	casEngine, err := storage.NewCASEngine("storage/cas")
	if err != nil {
		log.Fatalf("Failed to init CAS Engine: %v", err)
	}

	sessionMgr, err := upload.NewSessionManager("storage/tmp")
	if err != nil {
		log.Fatalf("Failed to init Session Manager: %v", err)
	}

	fileCtrl := &controllers.FileController{
		DB:  dbEngine,
		CAS: casEngine,
	}
	fileCtrl.SeedInitialData()

	app.GET("/api/files", fileCtrl.GetFiles)
	app.GET("/api/folders", fileCtrl.GetFolders)
	app.GET("/api/files/:id/download", fileCtrl.DownloadFile)
	app.DELETE("/api/files/:id", fileCtrl.DeleteFile)

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
	}
	app.POST("/api/purge", secCtrl.PanicPurge)

	shuffler := &storage.ChitinShuffler{CAS: casEngine}
	shuffler.StartBackgroundWorker(context.Background(), 6*time.Hour)

	app.POST("/login", auth.LoginMock)

	// Protected Upload Routes
	uploadGroup := app.Group("/upload", auth.VaultKeyMiddleware())
	uploadGroup.POST("/init", uploadCtrl.InitSession)
	uploadGroup.PUT("/:session_id", uploadCtrl.UploadChunk)
	uploadGroup.GET("/:session_id", uploadCtrl.GetStatus)

	app.GET("/", func(c *echo.Context) error {
		return components.Dashboard(c).Render(c.Request().Context(), c.Response())
	})

	log.Println("Starting Hornetz Drive on :" + port + "...")
	log.Fatal(app.Start(":" + port))
}
