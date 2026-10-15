package controllers

import (
	"crypto/rand"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/download"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
	"ztatic-go-framework/realtime"
)

type SecurityController struct {
	CAS         *storage.CASEngine
	Broker      *realtime.MemoryBroker
	DB          *data.DBEngine
	TmpDir      string
	SessionMgr  *upload.SessionManager
	UploadCtrl  *UploadController
	DownloadMgr *download.DownloadManager
}

type PanicPurgeRequest struct {
	Password string `json:"password" form:"password"`
}

// shredFile securely overwrites file contents with random bytes, syncs to disk,
// truncates to 0 bytes, and unlinks the file from the filesystem.
func shredFile(path string, buf []byte) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0666)
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	size := info.Size()
	var written int64 = 0
	for written < size {
		toWrite := int64(len(buf))
		if size-written < toWrite {
			toWrite = size - written
		}
		if _, err := rand.Read(buf[:toWrite]); err != nil {
			break
		}
		n, errWrite := f.Write(buf[:toWrite])
		if errWrite != nil || n <= 0 {
			break
		}
		written += int64(n)
	}
	_ = f.Sync()
	_ = f.Truncate(0)
	_ = f.Close()
	return os.Remove(path)
}

// pruneEmptyDirs walks the directory tree and removes empty subdirectories (deepest first).
func pruneEmptyDirs(root string) {
	if root == "" {
		return
	}
	var dirs []string
	_ = filepath.Walk(root, func(p string, info fs.FileInfo, err error) error {
		if err == nil && info != nil && info.IsDir() && p != root {
			dirs = append(dirs, p)
		}
		return nil
	})
	// Sort by path length descending so deepest subdirectories are pruned first
	sort.Slice(dirs, func(i, j int) bool {
		return len(dirs[i]) > len(dirs[j])
	})
	for _, d := range dirs {
		_ = os.Remove(d) // os.Remove only succeeds if directory is completely empty
	}
}

// shredDirectoryFiles securely overwrites and deletes all regular files in a directory tree.
func shredDirectoryFiles(root string, buf []byte) error {
	if root == "" {
		return nil
	}
	return filepath.Walk(root, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			_ = shredFile(path, buf)
		}
		return nil
	})
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

	// 2. Abort all active downloads so no ongoing network workers continue writing data
	if sc.DownloadMgr != nil {
		sc.DownloadMgr.CancelAllTasks()
	}

	// 3. Overwrite all physical CAS files with random bytes and prune empty directory shards (BUG-SEC-19)
	chunk := make([]byte, 1024*1024) // 1MB reusable buffer
	if sc.CAS != nil && sc.CAS.BaseDir != "" {
		_ = shredDirectoryFiles(sc.CAS.BaseDir, chunk)
		pruneEmptyDirs(sc.CAS.BaseDir)
		sc.CAS.ClearCache()
	}

	// 4. Clear database records so database doesn't reference shredded files
	if sc.DB != nil && sc.DB.SQL != nil {
		_, _ = sc.DB.SQL.Exec("DELETE FROM files")
		_, _ = sc.DB.SQL.Exec("DELETE FROM folders WHERE id NOT IN ('f1', 'f2', 'f3')")
	}

	// Invalidate Vault folder cache
	if sc.UploadCtrl != nil && sc.UploadCtrl.FileCtrl != nil {
		sc.UploadCtrl.FileCtrl.InvalidateVaultCache()
	}

	// 5. Shred cached thumbnail previews with disk sector overwriting (BUG-SEC-19)
	_ = shredDirectoryFiles("storage/thumbnails", chunk)
	pruneEmptyDirs("storage/thumbnails")

	// 6. Shred temporary upload buffers and partial downloads with random byte overwrites (BUG-SEC-19)
	if sc.TmpDir != "" {
		_ = shredDirectoryFiles(sc.TmpDir, chunk)
		pruneEmptyDirs(sc.TmpDir)
	}
	if sc.DownloadMgr != nil && sc.DownloadMgr.TmpDir != "" && sc.DownloadMgr.TmpDir != sc.TmpDir {
		_ = shredDirectoryFiles(sc.DownloadMgr.TmpDir, chunk)
		pruneEmptyDirs(sc.DownloadMgr.TmpDir)
	}

	// 7. Purge all in-memory upload sessions and completed sessions
	if sc.SessionMgr != nil {
		sc.SessionMgr.PurgeAll()
	}
	if sc.UploadCtrl != nil {
		sc.UploadCtrl.PurgeAllSessions()
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "purged",
		"message": "Vault permanently shredded and database synchronized.",
	})
}
