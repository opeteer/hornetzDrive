package controllers

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/reconcile"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
)

type ReconcileController struct {
	DB         *data.DBEngine
	SessionMgr *upload.SessionManager
	CAS        *storage.CASEngine
	FileCtrl   *FileController
	QuotaBytes int64
}

type ReconcileTreeRequest struct {
	TargetFolderID string                `json:"target_folder_id"`
	RootName       string                `json:"root_name"`
	Tree           *reconcile.MerkleNode `json:"tree"`
}

func (rc *ReconcileController) isVaultFolder(folderID string) bool {
	if folderID == "f2" {
		return true
	}
	if folderID == "" || folderID == "f1" || folderID == "f3" {
		return false
	}
	if rc.FileCtrl != nil {
		return rc.FileCtrl.IsVaultFolder(folderID)
	}
	if rc.DB == nil || rc.DB.SQL == nil {
		return false
	}
	curr := folderID
	for i := 0; i < 50; i++ {
		var parentID sql.NullString
		err := rc.DB.SQL.QueryRow(rc.DB.Rebind("SELECT parent_id FROM folders WHERE id = ?"), curr).Scan(&parentID)
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

func (rc *ReconcileController) GetUserStorageUsed(ownerID int64) int64 {
	if rc.DB == nil || rc.DB.SQL == nil {
		return 0
	}
	var used int64
	query := rc.DB.Rebind("SELECT COALESCE(SUM(size), 0) FROM files WHERE owner_id = ? AND (is_deleted = FALSE OR is_deleted = 0)")
	_ = rc.DB.SQL.QueryRow(query, ownerID).Scan(&used)
	return used
}

// DiffTree handles POST /api/reconcile/tree-diff
// It receives a client-side Merkle tree, compares it top-down with the server state,
// and returns an actionable ReconciliationPlan.
func (rc *ReconcileController) DiffTree(c *echo.Context) error {
	var req ReconcileTreeRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request payload: "+err.Error())
	}

	if req.Tree == nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Tree payload is required")
	}

	if req.RootName != "" && req.Tree.Name == "" {
		req.Tree.Name = req.RootName
	}
	if req.Tree.Name == "" {
		req.Tree.Name = "uploaded_folder"
	}
	req.Tree.Name = filepath.Base(filepath.Clean(req.Tree.Name))

	// Vault lock check
	if rc.isVaultFolder(req.TargetFolderID) {
		cookie, err := c.Cookie("swarm_session")
		if err != nil || cookie == nil || !auth.GlobalSessionStore.HasKey(cookie.Value) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to upload to vault.")
		}
	}

	userID := auth.GetUserID(c)

	plan, err := reconcile.ReconcileTree(req.Tree, rc.SessionMgr, rc.DB, userID, req.TargetFolderID)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to reconcile tree: "+err.Error())
	}

	// Invalidate vault cache if new folders were provisioned
	if len(plan.FoldersProvisioned) > 0 && rc.FileCtrl != nil {
		rc.FileCtrl.InvalidateVaultCache()
	}

	// Enforce storage quota on remaining bytes
	if rc.QuotaBytes > 0 && plan.Summary.BytesRemaining > 0 {
		currentUsed := rc.GetUserStorageUsed(userID)
		if currentUsed+plan.Summary.BytesRemaining > rc.QuotaBytes {
			return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "Kapasitas penyimpanan terlampaui (Storage quota exceeded)")
		}
	}

	// Normalize root_folder_id if returned
	if plan.RootFolderID == "" && strings.TrimSpace(req.TargetFolderID) != "" {
		plan.RootFolderID = req.TargetFolderID
	}

	return c.JSON(http.StatusOK, plan)
}
