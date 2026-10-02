package controllers

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
)

type FileController struct {
	DB       *data.DBEngine
	CAS      *storage.CASEngine
	seedOnce sync.Once
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
	IsVault   bool   `json:"is_vault"`
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
	fc.seedOnce.Do(func() {
		fc.seedInitialDataInternal()
	})
}

func (fc *FileController) seedInitialDataInternal() {
	if fc.DB == nil || fc.DB.SQL == nil {
		return
	}

	// Ensure schema columns exist
	_, _ = fc.DB.SQL.Exec("ALTER TABLE files ADD COLUMN is_starred BOOLEAN DEFAULT FALSE")
	_, _ = fc.DB.SQL.Exec("ALTER TABLE files ADD COLUMN is_deleted BOOLEAN DEFAULT FALSE")

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
		('file_1', 1, 'f1', 'laporan_keuangan_q3_2026.pdf', 'application/pdf', 25690112, 'a8f3b2c91d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567', TRUE, FALSE),
		('file_2', 1, 'f2', 'kunci_akses_master_vault.key', 'application/octet-stream', 4300, 'f9e8d7c6b5a432109876543210fedcba9876543210fedcba9876543210fedcba', FALSE, FALSE),
		('file_3', 1, 'f3', 'hornetz_system_architecture.pdf', 'application/pdf', 19084000, '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef', FALSE, FALSE),
		('file_4', 1, 'f3', 'cadangan_basis_data_swarm.tar.gz', 'application/gzip', 1503238553, '7766554433221100998877665544332211009988776655443322110099887766', FALSE, FALSE)` + onConflict)
}

func (fc *FileController) isVaultUnlocked(c *echo.Context) bool {
	cookie, err := c.Cookie("swarm_session")
	if err != nil || cookie == nil || !auth.GlobalSessionStore.HasKey(cookie.Value) {
		return false
	}
	return true
}

func (fc *FileController) IsVaultFolder(folderID string) bool {
	if folderID == "f2" {
		return true
	}
	if folderID == "" || folderID == "f1" || folderID == "f3" || fc.DB == nil || fc.DB.SQL == nil {
		return false
	}
	curr := folderID
	for i := 0; i < 50; i++ {
		var parentID sql.NullString
		err := fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT parent_id FROM folders WHERE id = ?"), curr).Scan(&parentID)
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

func (fc *FileController) GetAllVaultFolderIDs() []string {
	vaultIDs := []string{"f2"}
	if fc.DB == nil || fc.DB.SQL == nil {
		return vaultIDs
	}
	queue := []string{"f2"}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		rows, err := fc.DB.SQL.Query(fc.DB.Rebind("SELECT id FROM folders WHERE parent_id = ?"), curr)
		if err == nil {
			for rows.Next() {
				var id string
				if err := rows.Scan(&id); err == nil {
					vaultIDs = append(vaultIDs, id)
					queue = append(queue, id)
				}
			}
			rows.Close()
		}
	}
	return vaultIDs
}

func (fc *FileController) vaultExcludeFilter() string {
	ids := fc.GetAllVaultFolderIDs()
	if len(ids) == 0 {
		return "1=1"
	}
	escapedIDs := make([]string, len(ids))
	for i, id := range ids {
		escapedIDs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(id, "'", "''"))
	}
	return fmt.Sprintf("(folder_id IS NULL OR folder_id = '' OR folder_id NOT IN (%s))", strings.Join(escapedIDs, ","))
}

func (fc *FileController) GetFiles(c *echo.Context) error {
	fc.SeedInitialData()

	tab := c.QueryParam("tab")
	search := c.QueryParam("q")
	folderID := c.QueryParam("folder_id")

	isUnlocked := fc.isVaultUnlocked(c)

	// Verify vault authentication if accessing the vault tab or a folder inside the vault
	if tab == "vault" || fc.IsVaultFolder(folderID) {
		if !isUnlocked {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
		}
	}

	query := "SELECT id, owner_id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash, created_at, COALESCE(is_starred, FALSE), COALESCE(is_deleted, FALSE) FROM files WHERE 1=1"
	args := []interface{}{}

	if tab == "trash" {
		query += " AND is_deleted = TRUE"
		if !isUnlocked {
			query += " AND " + fc.vaultExcludeFilter()
		}
	} else {
		query += " AND is_deleted = FALSE"
		if tab == "starred" {
			query += " AND is_starred = TRUE"
			if !isUnlocked {
				query += " AND " + fc.vaultExcludeFilter()
			}
		} else if tab == "vault" {
			if folderID != "" {
				query += " AND folder_id = ?"
				args = append(args, folderID)
			} else {
				query += " AND folder_id = 'f2'"
			}
		} else {
			// Standard storage tab
			if folderID != "" {
				query += " AND folder_id = ?"
				args = append(args, folderID)
				if !isUnlocked && fc.IsVaultFolder(folderID) {
					query += " AND 1=0"
				}
			} else {
				// Root storage: exclude vault folders
				query += " AND " + fc.vaultExcludeFilter()
			}
		}
	}

	if search != "" {
		escaped := strings.ReplaceAll(search, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "%", "\\%")
		escaped = strings.ReplaceAll(escaped, "_", "\\_")
		pattern := "%" + escaped + "%"
		query += " AND (name LIKE ? ESCAPE '\\' OR cas_hash LIKE ? ESCAPE '\\')"
		args = append(args, pattern, pattern)
	}

	sortBy := c.QueryParam("sort_by")
	order := strings.ToLower(c.QueryParam("order"))
	orderDir := "ASC"
	if order == "desc" {
		orderDir = "DESC"
	}
	switch sortBy {
	case "name":
		query += " ORDER BY name " + orderDir
	case "size":
		query += " ORDER BY size " + orderDir
	case "created_at":
		query += " ORDER BY created_at " + orderDir
	default:
		if tab == "recent" {
			query += " ORDER BY created_at DESC"
		} else {
			query += " ORDER BY created_at DESC"
		}
	}

	limitStr := c.QueryParam("limit")
	offsetStr := c.QueryParam("offset")
	if limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			query += fmt.Sprintf(" LIMIT %d", limit)
			if offsetStr != "" {
				if offset, err := strconv.Atoi(offsetStr); err == nil && offset >= 0 {
					query += fmt.Sprintf(" OFFSET %d", offset)
				}
			}
		}
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
			f.IsVault = fc.IsVaultFolder(f.FolderID)
			files = append(files, f)
		}
	}

	return c.JSON(http.StatusOK, files)
}

func (fc *FileController) GetFolders(c *echo.Context) error {
	fc.SeedInitialData()

	tab := c.QueryParam("tab")
	parentID := c.QueryParam("parent_id")
	search := c.QueryParam("q")

	isUnlocked := fc.isVaultUnlocked(c)

	// Verify vault authentication if accessing the vault tab or a vault subfolder
	if tab == "vault" || fc.IsVaultFolder(parentID) {
		if !isUnlocked {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
		}
	}

	query := `
		SELECT f.id, f.owner_id, COALESCE(f.parent_id, ''), f.name, COUNT(fi.id) as file_count, f.created_at 
		FROM folders f 
		LEFT JOIN files fi ON fi.folder_id = f.id AND fi.is_deleted = FALSE
		WHERE 1=1`
	
	args := []interface{}{}

	if parentID != "" {
		query += " AND f.parent_id = ?"
		args = append(args, parentID)
		if !isUnlocked && fc.IsVaultFolder(parentID) {
			query += " AND 1=0"
		}
	} else if tab == "vault" {
		query += " AND f.id = 'f2'"
	} else {
		query += " AND f.id != 'f2' AND (f.parent_id IS NULL OR f.parent_id = '')"
		if !isUnlocked {
			vaultIDs := fc.GetAllVaultFolderIDs()
			escapedIDs := make([]string, len(vaultIDs))
			for i, vID := range vaultIDs {
				escapedIDs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(vID, "'", "''"))
			}
			query += fmt.Sprintf(" AND f.id NOT IN (%s)", strings.Join(escapedIDs, ","))
		}
	}

	if search != "" {
		escaped := strings.ReplaceAll(search, "\\", "\\\\")
		escaped = strings.ReplaceAll(escaped, "%", "\\%")
		escaped = strings.ReplaceAll(escaped, "_", "\\_")
		query += " AND f.name LIKE ? ESCAPE '\\'"
		args = append(args, "%"+escaped+"%")
	}

	query += " GROUP BY f.id, f.owner_id, f.parent_id, f.name, f.created_at"

	sortBy := c.QueryParam("sort_by")
	order := strings.ToLower(c.QueryParam("order"))
	orderDir := "ASC"
	if order == "desc" {
		orderDir = "DESC"
	}
	switch sortBy {
	case "name":
		query += " ORDER BY f.name " + orderDir
	case "created_at":
		query += " ORDER BY f.created_at " + orderDir
	default:
		query += " ORDER BY f.created_at DESC"
	}
	
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

func parseRangeHeader(rangeHeader string, totalSize int64) (start int64, end int64, satisfiable bool, isRange bool) {
	if !strings.HasPrefix(rangeHeader, "bytes=") {
		return 0, totalSize - 1, false, false
	}
	ranges := strings.TrimPrefix(rangeHeader, "bytes=")
	parts := strings.Split(ranges, "-")
	if len(parts) != 2 {
		return 0, totalSize - 1, false, false
	}

	// Suffix range: bytes=-500 (last 500 bytes)
	if parts[0] == "" && parts[1] != "" {
		suffixLen, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || suffixLen <= 0 {
			return 0, 0, false, true
		}
		if totalSize <= 0 {
			return 0, 0, false, true
		}
		if suffixLen > totalSize {
			suffixLen = totalSize
		}
		start = totalSize - suffixLen
		end = totalSize - 1
		return start, end, true, true
	}

	// Regular range: bytes=start-end or bytes=start-
	s, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || s < 0 || s >= totalSize {
		return 0, 0, false, true
	}
	start = s
	end = totalSize - 1
	if parts[1] != "" {
		e, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil || e < start {
			return 0, 0, false, true
		}
		if e < totalSize {
			end = e
		}
	}
	return start, end, true, true
}

func (fc *FileController) DownloadFile(c *echo.Context) error {
	id := c.Param("id")
	var f FileRecord
	query := fc.DB.Rebind("SELECT id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash FROM files WHERE id = ? AND is_deleted = FALSE")
	err := fc.DB.SQL.QueryRow(query, id).Scan(&f.ID, &f.FolderID, &f.Name, &f.MimeType, &f.Size, &f.CasHash)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	// Protect confidential Vault files: require active unlocked vault session
	if fc.IsVaultFolder(f.FolderID) {
		if !fc.isVaultUnlocked(c) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to download this file.")
		}
	}

	safeName := strings.ReplaceAll(f.Name, `"`, `_`)
	safeName = strings.ReplaceAll(safeName, `\`, `_`)
	safeName = strings.ReplaceAll(safeName, "\r", "")
	safeName = strings.ReplaceAll(safeName, "\n", "")

	c.Response().Header().Set("Accept-Ranges", "bytes")

	var file *os.File
	if fc.CAS != nil {
		path := fc.CAS.Path(f.CasHash)
		file, err = os.Open(path)
	} else {
		err = os.ErrNotExist
	}
	if err != nil {
		// Fallback for mock files: set Content-Length to actual mock body size to prevent connection hangs
		mockBody := []byte("Decrypted Content of " + f.Name)
		totalSize := int64(len(mockBody))
		c.Response().Header().Set("Content-Type", "text/plain; charset=utf-8")
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", safeName))

		if rangeHeader := c.Request().Header.Get("Range"); rangeHeader != "" {
			start, end, satisfiable, isRange := parseRangeHeader(rangeHeader, totalSize)
			if isRange {
				if !satisfiable {
					c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes */%d", totalSize))
					return c.NoContent(http.StatusRequestedRangeNotSatisfiable)
				}
				chunkLen := end - start + 1
				c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
				c.Response().Header().Set("Content-Length", strconv.FormatInt(chunkLen, 10))
				c.Response().WriteHeader(http.StatusPartialContent)
				_, err = c.Response().Write(mockBody[start : end+1])
				return err
			}
		}
		c.Response().Header().Set("Content-Length", strconv.Itoa(len(mockBody)))
		return c.String(http.StatusOK, string(mockBody))
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
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", safeName))

	// RFC 7233 Range request handling for decrypted stream
	if rangeHeader := c.Request().Header.Get("Range"); rangeHeader != "" {
		start, end, satisfiable, isRange := parseRangeHeader(rangeHeader, f.Size)
		if isRange {
			if !satisfiable {
				c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes */%d", f.Size))
				return c.NoContent(http.StatusRequestedRangeNotSatisfiable)
			}
			if start > 0 {
				if err := decStream.SeekTo(start); err != nil {
					return echo.NewHTTPError(http.StatusInternalServerError, "failed to seek in encrypted stream")
				}
			}
			chunkLen := end - start + 1
			c.Response().Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, f.Size))
			c.Response().Header().Set("Content-Length", strconv.FormatInt(chunkLen, 10))
			c.Response().WriteHeader(http.StatusPartialContent)
			_, err = io.CopyN(c.Response(), decStream, chunkLen)
			return err
		}
	}

	// Always set Content-Length (including 0 for empty files)
	c.Response().Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	_, err = io.Copy(c.Response(), decStream)
	return err
}

func (fc *FileController) DeleteFile(c *echo.Context) error {
	id := c.Param("id")
	permanent := c.QueryParam("permanent") == "true"

	var folderID string
	_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COALESCE(folder_id, '') FROM files WHERE id = ? AND owner_id = ?"), id, 1).Scan(&folderID)
	if fc.IsVaultFolder(folderID) && !fc.isVaultUnlocked(c) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
	}

	if permanent {
		var casHash string
		_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT cas_hash FROM files WHERE id = ? AND owner_id = ?"), id, 1).Scan(&casHash)

		query := fc.DB.Rebind("DELETE FROM files WHERE id = ? AND owner_id = ?")
		res, err := fc.DB.SQL.Exec(query, id, 1)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file: "+err.Error())
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			return echo.NewHTTPError(http.StatusNotFound, "File not found")
		}

		if casHash != "" && storage.IsValidHash(casHash) {
			var count int
			_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COUNT(*) FROM files WHERE cas_hash = ?"), casHash).Scan(&count)
			if count == 0 && fc.CAS != nil {
				_ = os.Remove(fc.CAS.Path(casHash))
			}
		}
		return c.JSON(http.StatusOK, map[string]string{"status": "permanently_deleted"})
	}

	// Soft delete: move to trash
	query := fc.DB.Rebind("UPDATE files SET is_deleted = TRUE WHERE id = ? AND owner_id = ?")
	res, err := fc.DB.SQL.Exec(query, id, 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to move file to trash: "+err.Error())
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "trashed"})
}

func (fc *FileController) RestoreFile(c *echo.Context) error {
	id := c.Param("id")

	var folderID string
	_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COALESCE(folder_id, '') FROM files WHERE id = ? AND owner_id = ?"), id, 1).Scan(&folderID)
	if fc.IsVaultFolder(folderID) && !fc.isVaultUnlocked(c) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
	}

	query := fc.DB.Rebind("UPDATE files SET is_deleted = FALSE WHERE id = ? AND owner_id = ?")
	res, err := fc.DB.SQL.Exec(query, id, 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to restore file: "+err.Error())
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "restored"})
}

func (fc *FileController) StarFile(c *echo.Context) error {
	id := c.Param("id")

	var folderID string
	_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COALESCE(folder_id, '') FROM files WHERE id = ? AND owner_id = ?"), id, 1).Scan(&folderID)
	if fc.IsVaultFolder(folderID) && !fc.isVaultUnlocked(c) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
	}

	query := fc.DB.Rebind("UPDATE files SET is_starred = CASE WHEN is_starred = TRUE THEN FALSE ELSE TRUE END WHERE id = ? AND owner_id = ? AND is_deleted = FALSE")
	res, err := fc.DB.SQL.Exec(query, id, 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to toggle star: "+err.Error())
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		var isDeleted bool
		errCheck := fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT is_deleted FROM files WHERE id = ? AND owner_id = ?"), id, 1).Scan(&isDeleted)
		if errCheck == nil && isDeleted {
			return echo.NewHTTPError(http.StatusBadRequest, "Cannot star a deleted file")
		}
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "starred_toggled"})
}

func (fc *FileController) EmptyTrash(c *echo.Context) error {
	isUnlocked := fc.isVaultUnlocked(c)
	filterClause := "owner_id = ? AND is_deleted = TRUE"
	if !isUnlocked {
		filterClause += " AND " + fc.vaultExcludeFilter()
	}

	rows, err := fc.DB.SQL.Query(fc.DB.Rebind("SELECT cas_hash FROM files WHERE "+filterClause), 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to query trash: "+err.Error())
	}
	defer rows.Close()

	hashes := []string{}
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err == nil && h != "" {
			hashes = append(hashes, h)
		}
	}

	res, err := fc.DB.SQL.Exec(fc.DB.Rebind("DELETE FROM files WHERE "+filterClause), 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to empty trash: "+err.Error())
	}
	count, _ := res.RowsAffected()

	if fc.CAS != nil {
		for _, h := range hashes {
			if storage.IsValidHash(h) {
				var refCount int
				_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COUNT(*) FROM files WHERE cas_hash = ?"), h).Scan(&refCount)
				if refCount == 0 {
					_ = os.Remove(fc.CAS.Path(h))
				}
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]interface{}{
		"status":        "trash_emptied",
		"deleted_count": count,
	})
}

func (fc *FileController) GetStorageStats(c *echo.Context) error {
	fc.SeedInitialData()

	var totalBytes sql.NullInt64
	var fileCount int
	isUnlocked := fc.isVaultUnlocked(c)

	filterClause := "owner_id = ? AND is_deleted = FALSE"
	if !isUnlocked {
		filterClause += " AND " + fc.vaultExcludeFilter()
	}

	query := fc.DB.Rebind("SELECT COALESCE(SUM(size), 0), COUNT(*) FROM files WHERE " + filterClause)
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
	ext := strings.ToLower(getFileExt(name))
	switch ext {
	case "pdf":
		return "📄"
	case "key", "pem", "crt", "pub":
		return "🔑"
	case "tar.gz", "zip", "tar", "gz", "7z", "rar":
		return "📦"
	case "png", "jpg", "jpeg", "gif", "webp", "svg":
		return "🖼️"
	case "mp4", "mkv", "webm", "mov", "avi":
		return "🎬"
	case "mp3", "wav", "ogg", "flac":
		return "🎵"
	case "go", "js", "ts", "html", "css", "json", "sql", "sh", "py", "md", "rs", "cpp", "c":
		return "💻"
	case "xls", "xlsx", "csv":
		return "📊"
	case "doc", "docx", "txt", "rtf":
		return "📄"
	default:
		if strings.HasPrefix(mime, "image/") {
			return "🖼️"
		} else if strings.HasPrefix(mime, "video/") {
			return "🎬"
		} else if strings.HasPrefix(mime, "audio/") {
			return "🎵"
		}
		return "📄"
	}
}

func getFileExt(name string) string {
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i+1:]
		}
	}
	return "FILE"
}

type CreateFolderRequest struct {
	Name     string `json:"name"`
	ParentID string `json:"parent_id"`
}

func (fc *FileController) CreateFolder(c *echo.Context) error {
	var req CreateFolderRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Folder name cannot be empty")
	}
	cleanName := filepath.Base(filepath.Clean(name))
	if cleanName == "." || cleanName == "/" || cleanName == "" {
		cleanName = "Folder Baru"
	}

	if req.ParentID != "" {
		// Enforce vault authentication if creating inside vault or any vault subfolder
		if fc.IsVaultFolder(req.ParentID) {
			if !fc.isVaultUnlocked(c) {
				return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to create folder in vault.")
			}
		}

		var parentExists bool
		err := fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM folders WHERE id = ?)"), req.ParentID).Scan(&parentExists)
		if err != nil || !parentExists {
			return echo.NewHTTPError(http.StatusBadRequest, "Invalid parent folder")
		}
	}

	// Prevent duplicate folder names under the same parent
	var exists bool
	var checkQuery string
	var checkArgs []interface{}
	if req.ParentID != "" {
		checkQuery = fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM folders WHERE parent_id = ? AND name = ?)")
		checkArgs = []interface{}{req.ParentID, cleanName}
	} else {
		checkQuery = fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM folders WHERE (parent_id IS NULL OR parent_id = '') AND name = ?)")
		checkArgs = []interface{}{cleanName}
	}
	_ = fc.DB.SQL.QueryRow(checkQuery, checkArgs...).Scan(&exists)
	if exists {
		return echo.NewHTTPError(http.StatusConflict, "Folder with this name already exists in the destination")
	}

	folderID := fmt.Sprintf("f_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
	query := fc.DB.Rebind("INSERT INTO folders (id, owner_id, parent_id, name) VALUES (?, 1, NULLIF(?, ''), ?)")
	_, err := fc.DB.SQL.Exec(query, folderID, req.ParentID, cleanName)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to create folder: "+err.Error())
	}

	return c.JSON(http.StatusCreated, map[string]string{
		"id":   folderID,
		"name": cleanName,
	})
}

func (fc *FileController) DeleteFolder(c *echo.Context) error {
	id := c.Param("id")

	// Block deletion of immutable system root folders
	if id == "f1" || id == "f2" || id == "f3" {
		return echo.NewHTTPError(http.StatusForbidden, "Folder sistem tidak dapat dihapus")
	}

	if fc.IsVaultFolder(id) {
		if !fc.isVaultUnlocked(c) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked.")
		}
	}

	// Collect all descendant folder IDs using BFS to prevent orphaned files
	allFolderIDs := []string{id}
	queue := []string{id}
	for len(queue) > 0 {
		currID := queue[0]
		queue = queue[1:]
		rows, err := fc.DB.SQL.Query(fc.DB.Rebind("SELECT id FROM folders WHERE parent_id = ? AND owner_id = ?"), currID, 1)
		if err == nil {
			for rows.Next() {
				var childID string
				if err := rows.Scan(&childID); err == nil {
					allFolderIDs = append(allFolderIDs, childID)
					queue = append(queue, childID)
				}
			}
			rows.Close()
		}
	}

	// Move all files in all folders to trash.
	// Set folder_id = NULL (or 'f2' for vault folders) so foreign key ON DELETE CASCADE does not wipe files
	isVault := fc.IsVaultFolder(id)
	for _, fID := range allFolderIDs {
		if isVault {
			_, _ = fc.DB.SQL.Exec(fc.DB.Rebind("UPDATE files SET is_deleted = TRUE, folder_id = 'f2' WHERE folder_id = ? AND owner_id = ?"), fID, 1)
		} else {
			_, _ = fc.DB.SQL.Exec(fc.DB.Rebind("UPDATE files SET is_deleted = TRUE, folder_id = NULL WHERE folder_id = ? AND owner_id = ?"), fID, 1)
		}
	}

	// Delete child subfolders first (reverse order)
	for i := len(allFolderIDs) - 1; i >= 0; i-- {
		_, _ = fc.DB.SQL.Exec(fc.DB.Rebind("DELETE FROM folders WHERE id = ? AND owner_id = ?"), allFolderIDs[i], 1)
	}

	return c.JSON(http.StatusOK, map[string]string{"status": "folder_deleted"})
}

type RenameFolderRequest struct {
	Name string `json:"name"`
}

func (fc *FileController) RenameFolder(c *echo.Context) error {
	id := c.Param("id")

	// Block renaming of immutable system root folders
	if id == "f1" || id == "f2" || id == "f3" {
		return echo.NewHTTPError(http.StatusForbidden, "Folder sistem tidak dapat diubah namanya")
	}

	if fc.IsVaultFolder(id) {
		if !fc.isVaultUnlocked(c) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked.")
		}
	}

	var req RenameFolderRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Folder name cannot be empty")
	}
	cleanName := filepath.Base(filepath.Clean(name))
	if cleanName == "." || cleanName == "/" || cleanName == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid folder name")
	}

	var parentID sql.NullString
	err := fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT parent_id FROM folders WHERE id = ? AND owner_id = ?"), id, 1).Scan(&parentID)
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "Folder not found")
	}

	var exists bool
	if parentID.Valid && parentID.String != "" {
		_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM folders WHERE parent_id = ? AND name = ? AND id != ?)"), parentID.String, cleanName, id).Scan(&exists)
	} else {
		_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM folders WHERE (parent_id IS NULL OR parent_id = '') AND name = ? AND id != ?)"), cleanName, id).Scan(&exists)
	}
	if exists {
		return echo.NewHTTPError(http.StatusConflict, "Folder with this name already exists")
	}

	res, err := fc.DB.SQL.Exec(fc.DB.Rebind("UPDATE folders SET name = ? WHERE id = ? AND owner_id = ?"), cleanName, id, 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to rename folder: "+err.Error())
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "Folder not found")
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "folder_renamed", "name": cleanName})
}


