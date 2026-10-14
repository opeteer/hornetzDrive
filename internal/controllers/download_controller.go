package controllers

import (
	"bytes"
	"database/sql"
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
	}

	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	req.URL = strings.TrimSpace(req.URL)
	if !download.IsDownloadLink(req.URL) {
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

	task, err := dc.Manager.StartDownload(c.Request().Context(), 1, folderID, req.URL, isVault, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	return c.JSON(http.StatusAccepted, task)
}

// GetDownloadStatus returns the progress and status of an ongoing or completed download.
func (dc *DownloadController) GetDownloadStatus(c *echo.Context) error {
	id := c.Param("id")
	task, found := dc.Manager.GetTask(id)
	if !found {
		return echo.NewHTTPError(http.StatusNotFound, "download task not found")
	}
	return c.JSON(http.StatusOK, task)
}

// CancelDownload cancels an in-progress download task.
func (dc *DownloadController) CancelDownload(c *echo.Context) error {
	id := c.Param("id")
	if !dc.Manager.CancelTask(id) {
		return echo.NewHTTPError(http.StatusNotFound, "download task not found")
	}
	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":  "cancelled",
		"message": "download cancelled successfully",
	})
}

// ParseLink analyzes a link and returns preview metadata (type, filename, info hash).
func (dc *DownloadController) ParseLink(c *echo.Context) error {
	var req struct {
		URL string `json:"url"`
	}
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid request body")
	}

	req.URL = strings.TrimSpace(req.URL)
	linkType, err := download.DetectLinkType(req.URL)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	resp := map[string]interface{}{
		"valid": true,
		"type":  linkType,
		"url":   req.URL,
	}

	if linkType == download.DownloadTypeMagnet {
		mag, err := download.ParseMagnetURI(req.URL)
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
		resp["name"] = download.ParseFilenameFromHeaders("", req.URL)
	}

	return c.JSON(http.StatusOK, resp)
}
