package controllers

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
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
	SessionMgr *upload.SessionManager
	CAS        *storage.CASEngine
	Broker     *realtime.MemoryBroker
	DB         *data.DBEngine
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

	if req.CasHash != "" && uc.CAS.Exists(req.CasHash) {
		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":   "completed",
			"message":  "0-second deduplication successful",
			"cas_hash": req.CasHash,
		})
	}

	sess, err := uc.SessionMgr.CreateSession(1, req.FolderID, req.Filename, req.MimeType, req.Size)
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

	f, err := os.OpenFile(sess.TempFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to open temp file")
	}
	defer f.Close()

	// Retrieve RAM-only Vault Key from middleware context
	vk := c.Get("vault_key").([]byte)

	// Apply Dynamo AES-256-GCM chunked encryption directly during upload stream
	encStream, err := crypto.NewEncryptStream(f, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initialize encryption stream")
	}

	written, err := io.Copy(encStream, c.Request().Body)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "chunk transfer failed")
	}

	sess.UploadedSize += written
	sess.LastActiveAt = time.Now()

	// SSE Realtime broadcast for Venom Speed
	percentage := (sess.UploadedSize * 100) / sess.ExpectedSize
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
		uc.SessionMgr.DeleteSession(sess.ID)

		if uc.DB != nil && uc.DB.SQL != nil {
			fileID := fmt.Sprintf("file_%d", time.Now().UnixNano())
			folderID := sess.FolderID
			if folderID == "" || folderID == "root" {
				folderID = "f1"
			}
			uc.DB.SQL.Exec("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES (?, 1, ?, ?, ?, ?, ?)",
				fileID, folderID, sess.Filename, sess.MimeType, sess.ExpectedSize, casHash)
		}

		return c.JSON(http.StatusOK, map[string]interface{}{
			"status":   "completed",
			"cas_hash": casHash,
		})
	}

	return c.JSON(308, map[string]interface{}{
		"status":   "incomplete",
		"uploaded": sess.UploadedSize,
	})
}

func (uc *UploadController) GetStatus(c *echo.Context) error {
	sessionID := c.Param("session_id")
	sess, exists := uc.SessionMgr.GetSession(sessionID)
	if !exists {
		return echo.NewHTTPError(http.StatusNotFound, "session not found")
	}

	return c.JSON(308, map[string]interface{}{
		"status":   "incomplete",
		"uploaded": sess.UploadedSize,
		"expected": sess.ExpectedSize,
	})
}
