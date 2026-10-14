package controllers

import (
	"bytes"
	"database/sql"
	"log/slog"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/download"
	"ztatic-go-framework/internal/storage"
)

// DownloadController handles REST API endpoints for remote link downloads.
type DownloadController struct {
	Manager *download.DownloadManager
	DB      *data.DBEngine
	CAS     *storage.CASEngine
}

func (dc *DownloadController) isVaultFolder(folderID string) bool {
	if folderID == "f2" {
		return true
	}
	if folderID == "" || folderID == "f1" || folderID == "f3" || dc.DB == nil || dc.DB.SQL == nil {
		return false
	}
	curr := folderID
	for i := 0; i < 50; i++ {
		var parentID sql.NullString
		err := dc.DB.SQL.QueryRow(dc.DB.Rebind("SELECT parent_id FROM folders WHERE id = ?"), curr).Scan(&parentID)
		if err != nil || !parentID.Valid || parentID.String == "" {
			return false
		}
		if parentID.String == "f2" {
			return true
		}
		curr = parentID.String
	}
	return false
}

func (dc *DownloadController) getVaultKey(c *echo.Context) ([]byte, bool) {
	if isAuth, _ := c.Get("vault_authenticated").(bool); isAuth {
		if vKey, ok := c.Get("vault_key").([]byte); ok && len(vKey) > 0 && !bytes.Equal(vKey, crypto.DummyVK()) {
			return vKey, true
		}
	}
	if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
		if key, exists := auth.GlobalSessionStore.GetKey(cookie.Value); exists && len(key) > 0 {
			return key, true
		}
	}
	return nil, false
}

// StartDownload initiates an asynchronous download from a direct URL or magnet link.
func (dc *DownloadController) StartDownload(c *echo.Context) error {
	var req struct {
		URL      string `json:"url"`
		FolderID string `json:"folder_id"`
		Filename string `json:"filename,omitempty"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	normURL := download.NormalizeLink(req.URL)
	if !download.IsDownloadLink(normURL) {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid download link: must start with http://, https://, or magnet:?")
	}

	folderID := req.FolderID
	if folderID == "root" {
		folderID = ""
	} else if folderID != "" && folderID != "f1" && folderID != "f2" && folderID != "f3" {
		if dc.DB != nil && dc.DB.SQL != nil {
			var count int
			query := dc.DB.Rebind("SELECT COUNT(*) FROM folders WHERE id = ?")
			_ = dc.DB.SQL.QueryRow(query, folderID).Scan(&count)
			if count == 0 {
				return echo.NewHTTPError(http.StatusBadRequest, "target folder not found")
			}
		}
	}

	isVault := dc.isVaultFolder(folderID)
	var vk []byte
	if isVault {
		key, unlocked := dc.getVaultKey(c)
		if !unlocked {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to download to vault.")
		}
		vk = key
	}

	userID := 1
	if uid, ok := c.Get("user_id").(int); ok && uid > 0 {
		userID = uid
	}

	task, err := dc.Manager.StartDownloadWithFilename(c.Request().Context(), userID, folderID, normURL, req.Filename, isVault, vk)
	if err != nil {
		slog.Error("failed to start download task", "error", err, "url", normURL)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	slog.Info("download task started", "task_id", task.ID, "url", normURL, "filename", task.Filename, "folder_id", folderID)
	return c.JSON(http.StatusAccepted, task)
}

// StartBatchDownload initiates multiple downloads concurrently from a list of URLs or pattern string.
func (dc *DownloadController) StartBatchDownload(c *echo.Context) error {
	var req struct {
		Input    string   `json:"input,omitempty"`
		URLs     []string `json:"urls,omitempty"`
		FolderID string   `json:"folder_id"`
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	urlsToProcess := req.URLs
	if len(urlsToProcess) == 0 && req.Input != "" {
		expanded, err := download.ExpandBatchLinks(req.Input)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		urlsToProcess = expanded
	}

	if len(urlsToProcess) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "no URLs provided for batch download")
	}

	folderID := req.FolderID
	if folderID == "root" {
		folderID = ""
	} else if folderID != "" && folderID != "f1" && folderID != "f2" && folderID != "f3" {
		if dc.DB != nil && dc.DB.SQL != nil {
			var count int
			query := dc.DB.Rebind("SELECT COUNT(*) FROM folders WHERE id = ?")
			_ = dc.DB.SQL.QueryRow(query, folderID).Scan(&count)
			if count == 0 {
				return echo.NewHTTPError(http.StatusBadRequest, "target folder not found")
			}
		}
	}

	isVault := dc.isVaultFolder(folderID)
	var vk []byte
	if isVault {
		key, unlocked := dc.getVaultKey(c)
		if !unlocked {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to download to vault.")
		}
		vk = key
	}

	userID := 1
	if uid, ok := c.Get("user_id").(int); ok && uid > 0 {
		userID = uid
	}

	tasks, err := dc.Manager.StartBatchDownload(c.Request().Context(), userID, folderID, urlsToProcess, isVault, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusAccepted, map[string]interface{}{
		"tasks": tasks,
		"count": len(tasks),
	})
}

// GetDownloadStatus returns the progress and status of an ongoing or completed download.
func (dc *DownloadController) GetDownloadStatus(c *echo.Context) error {
	id := c.Param("id")
	task, found := dc.Manager.GetTask(id)
	if !found {
		return echo.NewHTTPError(http.StatusNotFound, "download task not found")
	}
	if uid, ok := c.Get("user_id").(int); ok && uid > 0 && task.OwnerID != 0 && task.OwnerID != uid {
		return echo.NewHTTPError(http.StatusForbidden, "forbidden: cannot access another user's download task")
	}
	return c.JSON(http.StatusOK, task)
}

// CancelDownload cancels an in-progress download task.
func (dc *DownloadController) CancelDownload(c *echo.Context) error {
	id := c.Param("id")
	task, found := dc.Manager.GetTask(id)
	if !found {
		return echo.NewHTTPError(http.StatusNotFound, "download task not found")
	}
	if uid, ok := c.Get("user_id").(int); ok && uid > 0 && task.OwnerID != 0 && task.OwnerID != uid {
		return echo.NewHTTPError(http.StatusForbidden, "forbidden: cannot cancel another user's download task")
	}
	if !dc.Manager.CancelTask(id) {
		return echo.NewHTTPError(http.StatusBadRequest, "download task cannot be cancelled (may be already completed)")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "cancelled",
		"message": "download cancelled successfully",
	})
}

// ParseLink analyzes a link and returns preview metadata (type, filename, info hash, preflight probe).
func (dc *DownloadController) ParseLink(c *echo.Context) error {
	var req struct {
		URL string `json:"url"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	rawInput := strings.TrimSpace(req.URL)
	if rawInput == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "empty download URL")
	}

	normURL := download.NormalizeLink(rawInput)
	linkType, err := download.DetectLinkType(normURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	// Try preflight probing first
	probeRes, probeErr := download.ProbeLink(c.Request().Context(), nil, normURL)
	if probeErr == nil && probeRes != nil {
		resp := map[string]interface{}{
			"valid":          true,
			"type":           probeRes.Type,
			"url":            rawInput,
			"resolved_url":   probeRes.ResolvedURL,
			"final_url":      probeRes.FinalURL,
			"provider":       probeRes.Provider,
			"provider_icon":  probeRes.ProviderIcon,
			"name":           probeRes.Filename,
			"file_size":      probeRes.FileSize,
			"formatted_size": probeRes.FormattedSize,
			"mime_type":      probeRes.MimeType,
			"category":       probeRes.Category,
			"resumable":      probeRes.Resumable,
			"status_code":    probeRes.StatusCode,
			"is_torrent":     probeRes.IsTorrent,
			"is_batch":       probeRes.IsBatch,
			"batch_count":    probeRes.BatchCount,
			"batch_items":    probeRes.BatchItems,
		}

		if probeRes.Type == download.DownloadTypeMagnet {
			if mag, err := download.ParseMagnetURI(normURL); err == nil {
				resp["info_hash"] = mag.HexHash
				resp["trackers_count"] = len(mag.Trackers)
				resp["web_seeds_count"] = len(mag.WebSeeds)
				if mag.ExactLength > 0 {
					resp["exact_length"] = mag.ExactLength
				}
			}
		}
		return c.JSON(http.StatusOK, resp)
	}

	// Fallback to static resolution if probe connection failed (e.g. offline / mock test)
	resolved, err := download.ResolveLink(normURL)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	resp := map[string]interface{}{
		"valid":          true,
		"type":           linkType,
		"url":            rawInput,
		"resolved_url":   resolved.ResolvedURL,
		"domain":         resolved.Domain,
		"provider":       resolved.Provider,
		"provider_icon":  resolved.ProviderIcon,
		"name":           resolved.Filename,
		"formatted_size": "-",
		"category":       download.ClassifyCategory(resolved.Filename, ""),
	}

	if linkType == download.DownloadTypeMagnet {
		mag, err := download.ParseMagnetURI(normURL)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		resp["name"] = mag.DisplayName
		resp["info_hash"] = mag.HexHash
		resp["trackers_count"] = len(mag.Trackers)
		resp["web_seeds_count"] = len(mag.WebSeeds)
		if mag.ExactLength > 0 {
			resp["exact_length"] = mag.ExactLength
		}
	} else if linkType == download.DownloadTypeDirect {
		if resp["name"] == "" {
			resp["name"] = download.ParseFilenameFromHeaders("", resolved.ResolvedURL)
		}
	}

	return c.JSON(http.StatusOK, resp)
}
