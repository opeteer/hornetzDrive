package controllers

import (
	"crypto/rand"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"ztatic-go-framework/internal/auth"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/realtime"
)

type SecurityController struct {
	CAS    *storage.CASEngine
	Broker *realtime.MemoryBroker
}

func (sc *SecurityController) PanicPurge(c *echo.Context) error {
	// 1. Wipe RAM keys
	auth.GlobalSessionStore.Purge()
	fmt.Println("CRITICAL: Stinger Panic Purge Triggered! RAM Keys obliterated.")

	// 2. Overwrite all physical CAS files with random bytes
	err := filepath.Walk(sc.CAS.BaseDir, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}

		// Overwrite with os.urandom
		f, err := os.OpenFile(path, os.O_RDWR, 0666)
		if err == nil {
			size := info.Size()
			// Basic overwrite (1 pass)
			chunk := make([]byte, 1024*1024) // 1MB buffer
			var written int64 = 0
			for written < size {
				rand.Read(chunk)
				n, _ := f.Write(chunk)
				written += int64(n)
			}
			f.Sync()
			f.Close()
			os.Remove(path)
		}
		return nil
	})

	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Purge incomplete")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "purged",
		"message": "Vault permanently shredded.",
	})
}
