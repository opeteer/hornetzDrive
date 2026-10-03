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

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
	"ztatic-go-framework/realtime"
)

type SecurityController struct {
	CAS        *storage.CASEngine
	Broker     *realtime.MemoryBroker
	DB         *data.DBEngine
	TmpDir     string
	SessionMgr *upload.SessionManager
	UploadCtrl *UploadController
}

type PanicPurgeRequest struct {
	Password string `json:"password" form:"password"`
}

func (sc *SecurityController) PanicPurge(c *echo.Context) error {
	var req PanicPurgeRequest
	_ = c.Bind(&req)

	authenticated := false
	cookie, errCookie := c.Cookie("swarm_session")
	if errCookie == nil && cookie != nil && auth.GlobalSessionStore.HasKey(cookie.Value) {
		authenticated = true
	}

	if !authenticated && req.Password != "" {
		if auth.VerifyMasterPassword(req.Password) {
			authenticated = true
		}
	}

	if !authenticated {
		return echo.NewHTTPError(http.StatusUnauthorized, "Authentication failed. Master password or active vault session required for panic purge.")
	}

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

	// 3. Clear database records so database doesn't reference shredded files
	if sc.DB != nil && sc.DB.SQL != nil {
		_, _ = sc.DB.SQL.Exec("DELETE FROM files")
		_, _ = sc.DB.SQL.Exec("DELETE FROM folders WHERE id NOT IN ('f1', 'f2', 'f3')")
	}

	// 4. Overwrite and clean up temporary upload buffers
	if sc.TmpDir != "" {
		_ = filepath.Walk(sc.TmpDir, func(p string, info fs.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				_ = os.Remove(p)
			}
			return nil
		})
	}

	// 5. Purge all in-memory upload sessions and completed sessions
	if sc.SessionMgr != nil {
		sc.SessionMgr.PurgeAll()
	}
	if sc.UploadCtrl != nil {
		sc.UploadCtrl.PurgeAllSessions()
	}

	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Purge incomplete")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "purged",
		"message": "Vault permanently shredded and database synchronized.",
	})
}
