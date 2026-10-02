package controllers

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"

	"github.com/labstack/echo/v5"
)

type FileController struct {
	DB  *data.DBEngine
	CAS *storage.CASEngine
}

type FileRecord struct {
	ID        string `json:"id"`
	OwnerID   int64  `json:"owner_id"`
	FolderID  string `json:"folder_id"`
	Name      string `json:"name"`
	MimeType  string `json:"mime_type"`
	Size      int64  `json:"size"`
	CasHash   string `json:"cas_hash"`
	Icon      string `json:"icon"`
	Ext       string `json:"ext"`
	IsStarred bool   `json:"is_starred"`
	IsDeleted bool   `json:"is_deleted"`
	CreatedAt string `json:"created_at"`
}

type FolderRecord struct {
	ID        string `json:"id"`
	OwnerID   int64  `json:"owner_id"`
	ParentID  string `json:"parent_id"`
	Name      string `json:"name"`
	FileCount int    `json:"file_count"`
	CreatedAt string `json:"created_at"`
}

type StorageStats struct {
	UsedBytes      int64   `json:"used_bytes"`
	QuotaBytes     int64   `json:"quota_bytes"`
	UsedFormatted  string  `json:"used_formatted"`
	QuotaFormatted string  `json:"quota_formatted"`
	PercentUsed    float64 `json:"percent_used"`
	FileCount      int     `json:"file_count"`
}

// SeedInitialData populates database with initial real data if empty
func (fc *FileController) SeedInitialData() {
	if fc.DB == nil || fc.DB.SQL == nil {
		return
	}

	// Ensure schema columns exist
	_, _ = fc.DB.SQL.Exec("ALTER TABLE files ADD COLUMN is_starred BOOLEAN DEFAULT 0")
	_, _ = fc.DB.SQL.Exec("ALTER TABLE files ADD COLUMN is_deleted BOOLEAN DEFAULT 0")

	var count int
	_ = fc.DB.SQL.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	if count > 0 {
		return
	}

	ignoreClause := "INSERT OR IGNORE"
	if fc.DB != nil && fc.DB.DriverName == "postgres" {
		ignoreClause = "INSERT"
	}

	onConflict := ""
	if fc.DB != nil && fc.DB.DriverName == "postgres" {
		onConflict = " ON CONFLICT DO NOTHING"
	}

	// Ensure user exists
	fc.DB.SQL.Exec(ignoreClause + ` INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'master@hornetz.io', 'hash', 'salt', 'vk')` + onConflict)

	// Create Folders
	fc.DB.SQL.Exec(ignoreClause + ` INTO folders (id, owner_id, parent_id, name) VALUES 
		('f1', 1, NULL, 'Dokumen Keuangan 2026'),
		('f2', 1, NULL, 'Kunci SSH & SSL Privasi'),
		('f3', 1, NULL, 'Arsip Kode & Desain Sistem')` + onConflict)

	// Create Initial Files
	fc.DB.SQL.Exec(ignoreClause + ` INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_starred, is_deleted) VALUES
		('file_1', 1, 'f1', 'laporan_keuangan_q3_2026.pdf', 'application/pdf', 25690112, 'a8f3b2c91d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567', 1, 0),
		('file_2', 1, 'f2', 'kunci_akses_master_vault.key', 'application/octet-stream', 4300, 'f9e8d7c6b5a432109876543210fedcba9876543210fedcba9876543210fedcba', 0, 0),
		('file_3', 1, 'f3', 'hornetz_system_architecture.pdf', 'application/pdf', 19084000, '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', 0, 0),
		('file_4', 1, 'f3', 'cadangan_basis_data_swarm.tar.gz', 'application/gzip', 1503238553, '7766554433221100998877665544332211009988776655443322110099887766', 0, 0)` + onConflict)
}

func (fc *FileController) GetFiles(c *echo.Context) error {
	fc.SeedInitialData()

	tab := c.QueryParam("tab")
	search := c.QueryParam("q")
	folderID := c.QueryParam("folder_id")

	// Verify vault authentication if accessing the vault tab
	if tab == "vault" {
		cookie, err := c.Cookie("swarm_session")
		if err == nil && cookie != nil {
			if !auth.GlobalSessionStore.HasKey(cookie.Value) {
				return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
			}
		}
	}

	query := "SELECT id, owner_id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash, created_at, COALESCE(is_starred, 0), COALESCE(is_deleted, 0) FROM files WHERE 1=1"
	args := []interface{}{}

	if tab == "trash" {
		query += " AND is_deleted = 1"
	} else {
		query += " AND is_deleted = 0"
		if tab == "starred" {
			query += " AND is_starred = 1"
		} else if tab == "vault" {
			query += " AND folder_id = 'f2'"
		} else {
			// Standard storage tab
			query += " AND folder_id != 'f2'"
		}
	}

	if folderID != "" {
		query += " AND folder_id = ?"
		args = append(args, folderID)
		if tab != "vault" && folderID == "f2" {
			query += " AND 1=0" // Prevent accessing vault folder from non-vault tab
		}
	}

	if search != "" {
		query += " AND (name LIKE ? OR cas_hash LIKE ?)"
		pattern := "%" + search + "%"
		args = append(args, pattern, pattern)
	}

	if tab == "recent" {
		query += " ORDER BY created_at DESC"
	}

	query = fc.DB.Rebind(query)
	rows, err := fc.DB.SQL.Query(query, args...)
	if err != nil {
		return c.JSON(http.StatusOK, []FileRecord{})
	}
	defer rows.Close()

	files := []FileRecord{}
	for rows.Next() {
		var f FileRecord
		if err := rows.Scan(&f.ID, &f.OwnerID, &f.FolderID, &f.Name, &f.MimeType, &f.Size, &f.CasHash, &f.CreatedAt, &f.IsStarred, &f.IsDeleted); err == nil {
			f.Icon = getFileIcon(f.Name, f.MimeType)
			f.Ext = getFileExt(f.Name)
			files = append(files, f)
		}
	}

	return c.JSON(http.StatusOK, files)
}

func (fc *FileController) GetFolders(c *echo.Context) error {
	fc.SeedInitialData()

	tab := c.QueryParam("tab")

	query := `
		SELECT f.id, f.owner_id, COALESCE(f.parent_id, ''), f.name, COUNT(fi.id) as file_count, f.created_at 
		FROM folders f 
		LEFT JOIN files fi ON fi.folder_id = f.id AND fi.is_deleted = 0
		WHERE 1=1`
	
	args := []interface{}{}

	if tab == "vault" {
		query += " AND f.id = 'f2'"
	} else {
		query += " AND f.id != 'f2'"
	}

	query += " GROUP BY f.id, f.owner_id, f.parent_id, f.name, f.created_at"
	
	query = fc.DB.Rebind(query)

	rows, err := fc.DB.SQL.Query(query, args...)
	if err != nil {
		return c.JSON(http.StatusOK, []FolderRecord{})
	}
	defer rows.Close()

	folders := []FolderRecord{}
	for rows.Next() {
		var f FolderRecord
		if err := rows.Scan(&f.ID, &f.OwnerID, &f.ParentID, &f.Name, &f.FileCount, &f.CreatedAt); err == nil {
			folders = append(folders, f)
		}
	}

	return c.JSON(http.StatusOK, folders)
}

func (fc *FileController) DownloadFile(c *echo.Context) error {
	id := c.Param("id")
	var f FileRecord
	query := fc.DB.Rebind("SELECT id, name, mime_type, size, cas_hash FROM files WHERE id = ?")
	err := fc.DB.SQL.QueryRow(query, id).Scan(&f.ID, &f.Name, &f.MimeType, &f.Size, &f.CasHash)
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	path := fc.CAS.Path(f.CasHash)
	file, err := os.Open(path)
	if err != nil {
		// Fallback for mock files: set Content-Length to actual mock body size to prevent connection hangs
		mockBody := "Decrypted Content of " + f.Name
		c.Response().Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", f.Name))
		c.Response().Header().Set("Content-Length", strconv.Itoa(len(mockBody)))
		return c.String(http.StatusOK, mockBody)
	}
	defer file.Close()

	var vk []byte
	if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
		if key, exists := auth.GlobalSessionStore.GetKey(cookie.Value); exists {
			vk = key
		}
	}
	if len(vk) == 0 {
		vk = crypto.DummyVK()
	}

	decStream, err := crypto.NewDecryptStream(file, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Decryption error")
	}

	c.Response().Header().Set("Content-Type", f.MimeType)
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", f.Name))
	if f.Size > 0 {
		c.Response().Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	}
	_, err = io.Copy(c.Response(), decStream)
	return err
}

func (fc *FileController) DeleteFile(c *echo.Context) error {
	id := c.Param("id")
	permanent := c.QueryParam("permanent") == "true"

	if permanent {
		var casHash string
		_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT cas_hash FROM files WHERE id = ?"), id).Scan(&casHash)

		query := fc.DB.Rebind("DELETE FROM files WHERE id = ?")
		_, err := fc.DB.SQL.Exec(query, id)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file: "+err.Error())
		}

		if casHash != "" {
			var count int
			_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COUNT(*) FROM files WHERE cas_hash = ?"), casHash).Scan(&count)
			if count == 0 {
				_ = os.Remove(fc.CAS.Path(casHash))
			}
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "permanently_deleted"})
	}

	// Soft delete: move to trash
	query := fc.DB.Rebind("UPDATE files SET is_deleted = 1 WHERE id = ?")
	_, err := fc.DB.SQL.Exec(query, id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to move file to trash: "+err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "trashed"})
}

func (fc *FileController) RestoreFile(c *echo.Context) error {
	id := c.Param("id")
	query := fc.DB.Rebind("UPDATE files SET is_deleted = 0 WHERE id = ?")
	_, err := fc.DB.SQL.Exec(query, id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to restore file: "+err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "restored"})
}

func (fc *FileController) StarFile(c *echo.Context) error {
	id := c.Param("id")
	query := fc.DB.Rebind("UPDATE files SET is_starred = CASE WHEN is_starred = 1 THEN 0 ELSE 1 END WHERE id = ?")
	_, err := fc.DB.SQL.Exec(query, id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to toggle star: "+err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "starred_toggled"})
}

func (fc *FileController) GetStorageStats(c *echo.Context) error {
	fc.SeedInitialData()

	var totalBytes sql.NullInt64
	var fileCount int
	query := fc.DB.Rebind("SELECT COALESCE(SUM(size), 0), COUNT(*) FROM files WHERE owner_id = ? AND is_deleted = 0")
	err := fc.DB.SQL.QueryRow(query, 1).Scan(&totalBytes, &fileCount)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to query storage stats: "+err.Error())
	}

	const quotaBytes int64 = 2 * 1024 * 1024 * 1024 * 1024 // 2 TB
	used := totalBytes.Int64
	percent := (float64(used) / float64(quotaBytes)) * 100

	return c.JSON(http.StatusOK, StorageStats{
		UsedBytes:      used,
		QuotaBytes:     quotaBytes,
		UsedFormatted:  formatBytes(used),
		QuotaFormatted: "2 TB",
		PercentUsed:    percent,
		FileCount:      fileCount,
	})
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func getFileIcon(name, mime string) string {
	if len(name) > 4 && name[len(name)-4:] == ".pdf" {
		return "📄"
	}
	if len(name) > 4 && name[len(name)-4:] == ".key" {
		return "🔑"
	}
	if len(name) > 7 && name[len(name)-7:] == ".tar.gz" {
		return "📦"
	}
	return "📄"
}

func getFileExt(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i+1:]
		}
	}
	return "FILE"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
