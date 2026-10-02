package controllers

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/data"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
	"ztatic-go-framework/realtime"
)

type UploadController struct {
	SessionMgr        *upload.SessionManager
	CAS               *storage.CASEngine
	Broker            *realtime.MemoryBroker
	DB                *data.DBEngine
	completedSessions sync.Map
}

type ProgressBarComponent struct {
	Percentage int64
}

func (p ProgressBarComponent) Render(ctx context.Context, w io.Writer) error {
	_, err := fmt.Fprintf(w, `<div class="progress-bar amber-hazard" style="width: %d%%;"></div>`, p.Percentage)
	return err
}

func (uc *UploadController) InitSession(c *echo.Context) error {
	var req struct {
		Filename string `json:"filename"`
		MimeType string `json:"mime_type"`
		Size     int64  `json:"size"`
		FolderID string `json:"folder_id"`
		CasHash  string `json:"cas_hash"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request")
	}

	if req.Size < 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "file size cannot be negative")
	}

	cleanFilename := filepath.Base(filepath.Clean(req.Filename))
	if cleanFilename == "." || cleanFilename == "/" || cleanFilename == "" {
		cleanFilename = "untitled"
	}

	folderID := req.FolderID
	if folderID == "" || folderID == "root" {
		folderID = "f1"
	} else if folderID != "f1" && folderID != "f2" && folderID != "f3" {
		if uc.DB != nil && uc.DB.SQL != nil {
			var count int
			query := uc.DB.Rebind("SELECT COUNT(*) FROM folders WHERE id = ?")
			_ = uc.DB.SQL.QueryRow(query, folderID).Scan(&count)
			if count == 0 {
				return echo.NewHTTPError(http.StatusBadRequest, "folder not found")
			}
		}
	}

	if req.CasHash != "" {
		if !storage.IsValidHash(req.CasHash) {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid cas_hash format")
		}
		if uc.CAS.Exists(req.CasHash) {
			fileID := fmt.Sprintf("file_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
			if uc.DB != nil && uc.DB.SQL != nil {
				query := uc.DB.Rebind("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES (?, 1, ?, ?, ?, ?, ?)")
				_, err := uc.DB.SQL.Exec(query, fileID, folderID, cleanFilename, req.MimeType, req.Size, req.CasHash)
				if err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, "failed to record deduplicated file: "+err.Error())
				}
			}
			return c.JSON(http.StatusOK, map[string]interface{}{
				"status":   "completed",
				"message":  "0-second deduplication successful",
				"cas_hash": req.CasHash,
				"file_id":  fileID,
			})
		}
	}

	sess, err := uc.SessionMgr.CreateSession(1, folderID, cleanFilename, req.MimeType, req.Size)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initiate upload")
	}

	c.Response().Header().Set("Location", "/upload/"+sess.ID)
	return c.JSON(http.StatusCreated, map[string]interface{}{
		"session_id": sess.ID,
		"chunk_size": 1024 * 1024 * 2,
	})
}

func (uc *UploadController) UploadChunk(c *echo.Context) error {
	sessionID := c.Param("session_id")
	sess, exists := uc.SessionMgr.GetSession(sessionID)
	if !exists {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	sess.Mu.Lock()
	defer sess.Mu.Unlock()

	f, err := os.OpenFile(sess.TempFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to open temp file")
	}
	defer f.Close()

	bufWriter := bufio.NewWriterSize(f, 2*1024*1024)
	defer bufWriter.Flush()

	// Retrieve RAM-only Vault Key from middleware context
	var vk []byte
	if vKey, ok := c.Get("vault_key").([]byte); ok {
		vk = vKey
	}
	if len(vk) == 0 {
		vk = crypto.DummyVK()
	}

	// Apply Dynamo AES-256-GCM chunked encryption directly during upload stream
	encStream, err := crypto.NewEncryptStream(bufWriter, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initialize encryption stream")
	}

	transferBuf := make([]byte, 1024*1024)
	written, err := io.CopyBuffer(encStream, c.Request().Body, transferBuf)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "chunk transfer failed")
	}
	_ = bufWriter.Flush()

	// Prevent uploading more than declared size to eliminate stream desynchronization
	if sess.ExpectedSize > 0 && sess.UploadedSize+written > sess.ExpectedSize {
		return echo.NewHTTPError(http.StatusBadRequest, "uploaded bytes exceed declared session size")
	}

	sess.UploadedSize += written
	sess.LastActiveAt = time.Now()

	// SSE Realtime broadcast for Venom Speed
	var percentage int64 = 100
	if sess.ExpectedSize > 0 {
		percentage = (sess.UploadedSize * 100) / sess.ExpectedSize
	}
	uc.Broker.Publish(c.Request().Context(), "nest:user_1", fullstack.TurboStreamItem{
		Action:    fullstack.StreamUpdate,
		Target:    "venom-speed-" + sess.ID,
		Component: ProgressBarComponent{Percentage: percentage},
	})

	if sess.UploadedSize >= sess.ExpectedSize {
		casHash, err := uc.CAS.MoveToCAS(sess.TempFilePath)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "cas storage failed")
		}
		uc.completedSessions.Store(sess.ID, time.Now())
		uc.SessionMgr.DeleteSession(sess.ID)

		if uc.DB != nil && uc.DB.SQL != nil {
			fileID := fmt.Sprintf("file_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
			folderID := sess.FolderID
			if folderID == "" || folderID == "root" {
				folderID = "f1"
			}
			query := uc.DB.Rebind("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES (?, 1, ?, ?, ?, ?, ?)")
			_, err := uc.DB.SQL.Exec(query, fileID, folderID, sess.Filename, sess.MimeType, sess.UploadedSize, casHash)
			if err != nil {
				return echo.NewHTTPError(http.StatusInternalServerError, "failed to record file metadata in database: "+err.Error())
			}
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":   "completed",
			"cas_hash": casHash,
		})
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":   "incomplete",
		"uploaded": sess.UploadedSize,
	})
}

func (uc *UploadController) GetStatus(c *echo.Context) error {
	sessionID := c.Param("session_id")
	sess, exists := uc.SessionMgr.GetSession(sessionID)
	if !exists {
		if val, ok := uc.completedSessions.Load(sessionID); ok {
			completedAt := val.(time.Time)
			if time.Since(completedAt) < 2*time.Minute {
				return c.JSON(http.StatusOK, map[string]interface{}{
					"status": "completed",
				})
			}
			uc.completedSessions.Delete(sessionID)
		}
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":   "incomplete",
		"uploaded": sess.UploadedSize,
		"expected": sess.ExpectedSize,
	})
}

func (uc *UploadController) AbortSession(c *echo.Context) error {
	sessionID := c.Param("session_id")
	sess, exists := uc.SessionMgr.GetSession(sessionID)
	if !exists {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	sess.Mu.Lock()
	tempPath := sess.TempFilePath
	sess.Mu.Unlock()

	uc.SessionMgr.DeleteSession(sessionID)
	uc.completedSessions.Delete(sessionID)
	if tempPath != "" {
		_ = os.Remove(tempPath)
	}

	return c.JSON(http.StatusOK, map[string]string{
		"status":  "aborted",
		"message": "upload session cancelled and temporary data cleaned",
	})
}

