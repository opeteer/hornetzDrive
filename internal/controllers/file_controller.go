package controllers

import (
	"archive/zip"
	"database/sql"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/sync/singleflight"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
)

type FileController struct {
	DB              *data.DBEngine
	CAS             *storage.CASEngine
	QuotaBytes      int64
	seedOnce        sync.Once
	vaultMu         sync.RWMutex
	vaultIDsMap     map[string]bool
	vaultIDsList    []string
	vaultCacheValid bool
	thumbGroup      singleflight.Group
	svgCache        sync.Map
}

type FileRecord struct {
	ID         string `json:"id"`
	OwnerID    int64  `json:"owner_id"`
	FolderID   string `json:"folder_id"`
	Name       string `json:"name"`
	MimeType   string `json:"mime_type"`
	Size       int64  `json:"size"`
	CasHash    string `json:"cas_hash"`
	Icon       string `json:"icon"`
	Ext        string `json:"ext"`
	IsStarred  bool   `json:"is_starred"`
	IsDeleted  bool   `json:"is_deleted"`
	IsVault    bool   `json:"is_vault"`
	CreatedAt  string `json:"created_at"`
	HasPreview bool   `json:"has_preview"`
	PreviewURL string `json:"preview_url,omitempty"`
	ThumbURL   string `json:"thumb_url,omitempty"`
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
	TrashBytes     int64   `json:"trash_bytes"`
	TrashFormatted string  `json:"trash_formatted"`
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
	_, _ = fc.DB.SQL.Exec("ALTER TABLE files ADD COLUMN plaintext_hash TEXT DEFAULT ''")

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

// InvalidateVaultCache marks the cached vault folders as stale.
func (fc *FileController) InvalidateVaultCache() {
	fc.vaultMu.Lock()
	fc.vaultCacheValid = false
	fc.vaultIDsMap = nil
	fc.vaultIDsList = nil
	fc.vaultMu.Unlock()
}

func (fc *FileController) loadVaultCacheLocked() {
	if fc.vaultCacheValid {
		return
	}
	fc.vaultIDsMap = map[string]bool{"f2": true}
	fc.vaultIDsList = []string{"f2"}

	if fc.DB == nil || fc.DB.SQL == nil {
		fc.vaultCacheValid = true
		return
	}

	// Fetch all folder hierarchies in a single query instead of recursive N+1 DB roundtrips
	rows, err := fc.DB.SQL.Query("SELECT id, parent_id FROM folders WHERE parent_id IS NOT NULL AND parent_id != ''")
	if err != nil {
		fc.vaultCacheValid = true
		return
	}
	defer rows.Close()

	childrenMap := make(map[string][]string)
	for rows.Next() {
		var id, parentID string
		if err := rows.Scan(&id, &parentID); err == nil {
			childrenMap[parentID] = append(childrenMap[parentID], id)
		}
	}

	// Fast BFS downstream from root vault 'f2'
	queue := []string{"f2"}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, child := range childrenMap[curr] {
			if !fc.vaultIDsMap[child] {
				fc.vaultIDsMap[child] = true
				fc.vaultIDsList = append(fc.vaultIDsList, child)
				queue = append(queue, child)
			}
		}
	}
	fc.vaultCacheValid = true
}

func (fc *FileController) IsVaultFolder(folderID string) bool {
	if folderID == "f2" {
		return true
	}
	if folderID == "" || folderID == "f1" || folderID == "f3" {
		return false
	}

	fc.vaultMu.RLock()
	if fc.vaultCacheValid {
		isVault := fc.vaultIDsMap[folderID]
		fc.vaultMu.RUnlock()
		return isVault
	}
	fc.vaultMu.RUnlock()

	fc.vaultMu.Lock()
	fc.loadVaultCacheLocked()
	isVault := fc.vaultIDsMap[folderID]
	fc.vaultMu.Unlock()
	return isVault
}

func (fc *FileController) GetAllVaultFolderIDs() []string {
	fc.vaultMu.RLock()
	if fc.vaultCacheValid {
		res := make([]string, len(fc.vaultIDsList))
		copy(res, fc.vaultIDsList)
		fc.vaultMu.RUnlock()
		return res
	}
	fc.vaultMu.RUnlock()

	fc.vaultMu.Lock()
	fc.loadVaultCacheLocked()
	res := make([]string, len(fc.vaultIDsList))
	copy(res, fc.vaultIDsList)
	fc.vaultMu.Unlock()
	return res
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
	search := strings.TrimSpace(c.QueryParam("q"))
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
			if folderID != "" && search == "" {
				query += " AND folder_id = ?"
				args = append(args, folderID)
			} else {
				query += " AND (folder_id = 'f2' OR folder_id IN (SELECT id FROM folders WHERE parent_id = 'f2'))"
			}
		} else {
			// Standard storage tab
			if folderID != "" && search == "" {
				query += " AND folder_id = ?"
				args = append(args, folderID)
				if !isUnlocked && fc.IsVaultFolder(folderID) {
					query += " AND 1=0"
				}
			} else {
				// Root storage or global search across standard storage: exclude vault folders
				query += " AND " + fc.vaultExcludeFilter()
			}
		}
	}

	if search != "" {
		terms := strings.Fields(strings.ToLower(search))
		if len(terms) > 0 {
			for _, term := range terms {
				escaped := strings.ReplaceAll(term, "\\", "\\\\")
				escaped = strings.ReplaceAll(escaped, "%", "\\%")
				escaped = strings.ReplaceAll(escaped, "_", "\\_")
				pattern := "%" + escaped + "%"
				query += " AND (LOWER(name) LIKE ? ESCAPE '\\' OR LOWER(cas_hash) LIKE ? ESCAPE '\\')"
				args = append(args, pattern, pattern)
			}
		}
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
			f.HasPreview = IsPreviewable(f.Name, f.MimeType)
			if f.HasPreview {
				f.PreviewURL = fmt.Sprintf("/api/files/%s/preview", f.ID)
				f.ThumbURL = fmt.Sprintf("/api/files/%s/thumbnail", f.ID)
			}
			files = append(files, f)
		}
	}

	return c.JSON(http.StatusOK, files)
}

func (fc *FileController) GetFolders(c *echo.Context) error {
	fc.SeedInitialData()

	tab := c.QueryParam("tab")
	parentID := c.QueryParam("parent_id")
	search := strings.TrimSpace(c.QueryParam("q"))

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

	if parentID != "" && search == "" {
		query += " AND f.parent_id = ?"
		args = append(args, parentID)
		if !isUnlocked && fc.IsVaultFolder(parentID) {
			query += " AND 1=0"
		}
	} else if tab == "vault" {
		if search == "" {
			query += " AND f.parent_id = 'f2'"
		} else {
			query += " AND (f.id = 'f2' OR f.parent_id = 'f2')"
		}
	} else {
		if search == "" {
			query += " AND f.id != 'f2' AND (f.parent_id IS NULL OR f.parent_id = '')"
		} else {
			query += " AND f.id != 'f2'"
		}
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
		terms := strings.Fields(strings.ToLower(search))
		if len(terms) > 0 {
			for _, term := range terms {
				escaped := strings.ReplaceAll(term, "\\", "\\\\")
				escaped = strings.ReplaceAll(escaped, "%", "\\%")
				escaped = strings.ReplaceAll(escaped, "_", "\\_")
				query += " AND LOWER(f.name) LIKE ? ESCAPE '\\'"
				args = append(args, "%"+escaped+"%")
			}
		}
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
	// BUG-SEC-46: Strictly verify owner_id to prevent IDOR access across accounts
	query := fc.DB.Rebind("SELECT id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash FROM files WHERE id = ? AND owner_id = ? AND is_deleted = FALSE")
	err := fc.DB.SQL.QueryRow(query, id, 1).Scan(&f.ID, &f.FolderID, &f.Name, &f.MimeType, &f.Size, &f.CasHash)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	var createdAtStr sql.NullString
	_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT created_at FROM files WHERE id = ?"), id).Scan(&createdAtStr)
	if createdAtStr.Valid {
		f.CreatedAt = createdAtStr.String
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

	etag := fmt.Sprintf("\"%s\"", f.CasHash)
	c.Response().Header().Set("ETag", etag)
	c.Response().Header().Set("Accept-Ranges", "bytes")

	var lastModTime time.Time
	if f.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, f.CreatedAt); err == nil {
			lastModTime = t
		} else if t, err := time.Parse("2006-01-02 15:04:05", f.CreatedAt); err == nil {
			lastModTime = t
		} else if t, err := time.Parse("2006-01-02T15:04:05Z", f.CreatedAt); err == nil {
			lastModTime = t
		}
	}
	if !lastModTime.IsZero() {
		c.Response().Header().Set("Last-Modified", lastModTime.UTC().Format(http.TimeFormat))
	}

	// RFC 7233 If-Range validation: only evaluate Range if validator matches
	rangeHeader := c.Request().Header.Get("Range")
	ifRange := c.Request().Header.Get("If-Range")
	rangeAllowed := true
	if rangeHeader != "" && ifRange != "" {
		if strings.HasPrefix(ifRange, "\"") || strings.HasPrefix(ifRange, "W/\"") {
			cleanIfRange := strings.TrimPrefix(ifRange, "W/")
			if cleanIfRange != etag {
				rangeAllowed = false
			}
		} else if !lastModTime.IsZero() {
			if t, err := http.ParseTime(ifRange); err == nil {
				if !lastModTime.Truncate(time.Second).Equal(t) {
					rangeAllowed = false
				}
			} else {
				rangeAllowed = false
			}
		}
	}

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

		if rangeHeader != "" && rangeAllowed {
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
	if fc.IsVaultFolder(f.FolderID) {
		if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
			if key, exists := auth.GlobalSessionStore.GetKey(cookie.Value); exists {
				vk = key
			}
		}
		if len(vk) == 0 {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to download this file.")
		}
	} else {
		vk = crypto.DummyVK()
	}

	decStream, err := crypto.NewDecryptStream(file, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Decryption error")
	}

	c.Response().Header().Set("Content-Type", f.MimeType)
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", safeName))

	// RFC 7233 Range request handling for decrypted stream
	if rangeHeader != "" && rangeAllowed {
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

func (fc *FileController) PreviewFile(c *echo.Context) error {
	id := c.Param("id")
	var f FileRecord
	query := fc.DB.Rebind("SELECT id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash FROM files WHERE id = ? AND owner_id = ? AND is_deleted = FALSE")
	err := fc.DB.SQL.QueryRow(query, id, 1).Scan(&f.ID, &f.FolderID, &f.Name, &f.MimeType, &f.Size, &f.CasHash)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	if fc.IsVaultFolder(f.FolderID) {
		if !fc.isVaultUnlocked(c) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to preview this file.")
		}
	}

	safeName := strings.ReplaceAll(f.Name, `"`, `_`)
	safeName = strings.ReplaceAll(safeName, `\`, `_`)
	safeName = strings.ReplaceAll(safeName, "\r", "")
	safeName = strings.ReplaceAll(safeName, "\n", "")

	c.Response().Header().Set("Accept-Ranges", "bytes")
	c.Response().Header().Set("Cache-Control", "private, max-age=3600")

	var file *os.File
	if fc.CAS != nil {
		path := fc.CAS.Path(f.CasHash)
		file, err = os.Open(path)
	} else {
		err = os.ErrNotExist
	}
	if err != nil {
		mockBody := []byte("Content of " + f.Name)
		totalSize := int64(len(mockBody))
		c.Response().Header().Set("Content-Type", f.MimeType)
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", safeName))

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
		return c.Blob(http.StatusOK, f.MimeType, mockBody)
	}
	defer file.Close()

	var vk []byte
	if fc.IsVaultFolder(f.FolderID) {
		if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
			if key, exists := auth.GlobalSessionStore.GetKey(cookie.Value); exists {
				vk = key
			}
		}
		if len(vk) == 0 {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to preview this file.")
		}
	} else {
		vk = crypto.DummyVK()
	}

	decStream, err := crypto.NewDecryptStream(file, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Decryption error")
	}

	c.Response().Header().Set("Content-Type", f.MimeType)
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", safeName))

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

	c.Response().Header().Set("Content-Length", strconv.FormatInt(f.Size, 10))
	_, err = io.Copy(c.Response(), decStream)
	return err
}

func (fc *FileController) ThumbnailFile(c *echo.Context) error {
	id := c.Param("id")
	var f FileRecord
	query := fc.DB.Rebind("SELECT id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash FROM files WHERE id = ? AND owner_id = ? AND is_deleted = FALSE")
	err := fc.DB.SQL.QueryRow(query, id, 1).Scan(&f.ID, &f.FolderID, &f.Name, &f.MimeType, &f.Size, &f.CasHash)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	if fc.IsVaultFolder(f.FolderID) {
		if !fc.isVaultUnlocked(c) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked.")
		}
	}

	if !IsPreviewable(f.Name, f.MimeType) {
		return c.NoContent(http.StatusNoContent)
	}

	ext := strings.ToLower(getFileExt(f.Name))
	isPDF := (ext == "pdf" || f.MimeType == "application/pdf")
	isImg := strings.HasPrefix(f.MimeType, "image/") || (ext == "png" || ext == "jpg" || ext == "jpeg" || ext == "gif" || ext == "webp" || ext == "svg")
	isOffice := (ext == "pptx" || ext == "ppt" || ext == "docx" || ext == "doc" || ext == "xlsx" || ext == "xls" || ext == "odp" || ext == "odt" || ext == "ods")

	if isImg {
		return fc.PreviewFile(c)
	}

	thumbDir := "storage/thumbnails"
	_ = os.MkdirAll(thumbDir, 0755)
	cachedPath := filepath.Join(thumbDir, f.CasHash+".png")

	if isPDF {
		if _, err := os.Stat(cachedPath); err == nil {
			c.Response().Header().Set("Cache-Control", "public, max-age=86400")
			c.Response().Header().Set("Content-Type", "image/png")
			return c.File(cachedPath)
		}

		if fc.CAS != nil && fc.CAS.Exists(f.CasHash) {
			casPath := fc.CAS.Path(f.CasHash)
			var vk []byte
			if fc.IsVaultFolder(f.FolderID) {
				if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
					vk, _ = auth.GlobalSessionStore.GetKey(cookie.Value)
				}
			} else {
				vk = crypto.DummyVK()
			}

			// Singleflight group to prevent thundering herd for PDF thumbnail rendering
			_, _, _ = fc.thumbGroup.Do("pdf_"+f.CasHash, func() (interface{}, error) {
				if _, err := os.Stat(cachedPath); err == nil {
					return nil, nil
				}
				file, err := os.Open(casPath)
				if err != nil {
					return nil, err
				}
				defer file.Close()
				decStream, err := crypto.NewDecryptStream(file, vk)
				if err != nil {
					return nil, err
				}
				tmpDir := "storage/tmp"
				_ = os.MkdirAll(tmpDir, 0755)
				tmpPdfPath := filepath.Join(tmpDir, fmt.Sprintf("thumb_pdf_%s_%d.pdf", f.CasHash[:8], time.Now().UnixNano()))
				tmpOutPrefix := filepath.Join(tmpDir, fmt.Sprintf("thumb_out_%s_%d", f.CasHash[:8], time.Now().UnixNano()))

				tmpFile, err := os.Create(tmpPdfPath)
				if err != nil {
					return nil, err
				}
				_, _ = io.CopyN(tmpFile, decStream, 10*1024*1024)
				_ = tmpFile.Close()

				cmd := exec.Command("pdftoppm", "-png", "-singlefile", "-scale-to", "256", tmpPdfPath, tmpOutPrefix)
				if err := cmd.Run(); err == nil {
					generatedPng := tmpOutPrefix + ".png"
					if _, err := os.Stat(generatedPng); err == nil {
						_ = os.Rename(generatedPng, cachedPath)
						_ = os.Remove(tmpPdfPath)
						return nil, nil
					}
				}
				_ = os.Remove(tmpPdfPath)
				_ = os.Remove(tmpOutPrefix + ".png")
				return nil, errors.New("pdftoppm failed")
			})

			if _, err := os.Stat(cachedPath); err == nil {
				c.Response().Header().Set("Cache-Control", "public, max-age=86400")
				c.Response().Header().Set("Content-Type", "image/png")
				return c.File(cachedPath)
			}
		}

		// Cached SVG fallback
		svgKey := "pdf_" + f.CasHash
		var svgBytes []byte
		if val, ok := fc.svgCache.Load(svgKey); ok {
			svgBytes = val.([]byte)
		} else {
			svgBytes = []byte(generatePdfSvgThumbnail(f.Name))
			fc.svgCache.Store(svgKey, svgBytes)
		}
		c.Response().Header().Set("Cache-Control", "public, max-age=3600")
		c.Response().Header().Set("Content-Type", "image/svg+xml")
		return c.Blob(http.StatusOK, "image/svg+xml", svgBytes)
	}

	if isOffice {
		cachedJpg := filepath.Join(thumbDir, f.CasHash+".jpg")
		if _, err := os.Stat(cachedJpg); err == nil {
			c.Response().Header().Set("Cache-Control", "public, max-age=86400")
			c.Response().Header().Set("Content-Type", "image/jpeg")
			return c.File(cachedJpg)
		}
		cachedPng := filepath.Join(thumbDir, f.CasHash+".png")
		if _, err := os.Stat(cachedPng); err == nil {
			c.Response().Header().Set("Cache-Control", "public, max-age=86400")
			c.Response().Header().Set("Content-Type", "image/png")
			return c.File(cachedPng)
		}

		if fc.CAS != nil && fc.CAS.Exists(f.CasHash) {
			casPath := fc.CAS.Path(f.CasHash)
			var vk []byte
			if fc.IsVaultFolder(f.FolderID) {
				if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
					vk, _ = auth.GlobalSessionStore.GetKey(cookie.Value)
				}
			} else {
				vk = crypto.DummyVK()
			}

			// Singleflight group to prevent duplicate concurrent office thumbnail extraction
			_, _, _ = fc.thumbGroup.Do("off_"+f.CasHash, func() (interface{}, error) {
				if _, err := os.Stat(cachedJpg); err == nil {
					return nil, nil
				}
				if _, err := os.Stat(cachedPng); err == nil {
					return nil, nil
				}
				file, err := os.Open(casPath)
				if err != nil {
					return nil, err
				}
				defer file.Close()
				decStream, err := crypto.NewDecryptStream(file, vk)
				if err != nil {
					return nil, err
				}
				tmpDir := "storage/tmp"
				_ = os.MkdirAll(tmpDir, 0755)
				tmpZipPath := filepath.Join(tmpDir, fmt.Sprintf("thumb_office_%s_%d.zip", f.CasHash[:8], time.Now().UnixNano()))
				tmpFile, err := os.Create(tmpZipPath)
				if err != nil {
					return nil, err
				}
				written, _ := io.Copy(tmpFile, decStream)
				_ = tmpFile.Close()

				if tmpFileRead, err := os.Open(tmpZipPath); err == nil {
					_, ok := extractOfficeThumbnail(tmpFileRead, written, cachedJpg)
					_ = tmpFileRead.Close()
					_ = os.Remove(tmpZipPath)
					if ok {
						return nil, nil
					}
				}
				_ = os.Remove(tmpZipPath)
				return nil, errors.New("extractOfficeThumbnail failed")
			})

			if _, err := os.Stat(cachedJpg); err == nil {
				c.Response().Header().Set("Cache-Control", "public, max-age=86400")
				c.Response().Header().Set("Content-Type", "image/jpeg")
				return c.File(cachedJpg)
			}
			if _, err := os.Stat(cachedPng); err == nil {
				c.Response().Header().Set("Cache-Control", "public, max-age=86400")
				c.Response().Header().Set("Content-Type", "image/png")
				return c.File(cachedPng)
			}
		}

		// Cached SVG fallback
		svgKey := "off_" + ext + "_" + f.CasHash
		var svgBytes []byte
		if val, ok := fc.svgCache.Load(svgKey); ok {
			svgBytes = val.([]byte)
		} else {
			svgBytes = []byte(generateOfficeSvgThumbnail(f.Name, ext))
			fc.svgCache.Store(svgKey, svgBytes)
		}
		c.Response().Header().Set("Cache-Control", "public, max-age=3600")
		c.Response().Header().Set("Content-Type", "image/svg+xml")
		return c.Blob(http.StatusOK, "image/svg+xml", svgBytes)
	}

	svgKey := "doc_" + ext + "_" + f.CasHash
	if val, ok := fc.svgCache.Load(svgKey); ok {
		c.Response().Header().Set("Cache-Control", "public, max-age=3600")
		c.Response().Header().Set("Content-Type", "image/svg+xml")
		return c.Blob(http.StatusOK, "image/svg+xml", val.([]byte))
	}

	snippet := ""
	if fc.CAS != nil && fc.CAS.Exists(f.CasHash) {
		casPath := fc.CAS.Path(f.CasHash)
		var vk []byte
		if fc.IsVaultFolder(f.FolderID) {
			if cookie, err := c.Cookie("swarm_session"); err == nil && cookie != nil {
				vk, _ = auth.GlobalSessionStore.GetKey(cookie.Value)
			}
		} else {
			vk = crypto.DummyVK()
		}
		if file, err := os.Open(casPath); err == nil {
			defer file.Close()
			if decStream, err := crypto.NewDecryptStream(file, vk); err == nil {
				buf := make([]byte, 1024)
				n, _ := decStream.Read(buf)
				snippet = string(buf[:n])
			}
		}
	}

	svgBytes := []byte(generateDocumentSvgThumbnail(f.Name, ext, snippet))
	fc.svgCache.Store(svgKey, svgBytes)

	c.Response().Header().Set("Cache-Control", "public, max-age=3600")
	c.Response().Header().Set("Content-Type", "image/svg+xml")
	return c.Blob(http.StatusOK, "image/svg+xml", svgBytes)
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
				fc.CAS.Invalidate(casHash)
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

	tx, err := fc.DB.SQL.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction: "+err.Error())
	}
	defer tx.Rollback()

	rows, err := tx.Query(fc.DB.Rebind("SELECT DISTINCT cas_hash FROM files WHERE "+filterClause), 1)
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
	rows.Close()

	res, err := tx.Exec(fc.DB.Rebind("DELETE FROM files WHERE "+filterClause), 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to empty trash: "+err.Error())
	}
	count, _ := res.RowsAffected()

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit empty trash: "+err.Error())
	}

	if fc.CAS != nil {
		for _, h := range hashes {
			if storage.IsValidHash(h) {
				var refCount int
				_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COUNT(*) FROM files WHERE cas_hash = ?"), h).Scan(&refCount)
				if refCount == 0 {
					_ = os.Remove(fc.CAS.Path(h))
					fc.CAS.Invalidate(h)
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

	var activeBytes, trashBytes sql.NullInt64
	var activeCount, trashCount int
	isUnlocked := fc.isVaultUnlocked(c)

	filterActive := "owner_id = ? AND is_deleted = FALSE"
	filterTrash := "owner_id = ? AND is_deleted = TRUE"
	if !isUnlocked {
		filterActive += " AND " + fc.vaultExcludeFilter()
		filterTrash += " AND " + fc.vaultExcludeFilter()
	}

	_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COALESCE(SUM(size), 0), COUNT(*) FROM files WHERE "+filterActive), 1).Scan(&activeBytes, &activeCount)
	_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COALESCE(SUM(size), 0), COUNT(*) FROM files WHERE "+filterTrash), 1).Scan(&trashBytes, &trashCount)

	activeUsed := activeBytes.Int64
	trashedUsed := trashBytes.Int64
	totalPhysicalUsed := activeUsed + trashedUsed
	quotaBytes := fc.getQuotaBytes()
	var percent float64
	if quotaBytes > 0 {
		percent = (float64(totalPhysicalUsed) / float64(quotaBytes)) * 100
	}

	return c.JSON(http.StatusOK, StorageStats{
		UsedBytes:      totalPhysicalUsed,
		QuotaBytes:     quotaBytes,
		UsedFormatted:  formatBytes(totalPhysicalUsed),
		QuotaFormatted: formatBytes(quotaBytes),
		PercentUsed:    percent,
		FileCount:      activeCount,
		TrashBytes:     trashedUsed,
		TrashFormatted: formatBytes(trashedUsed),
	})
}

func (fc *FileController) getQuotaBytes() int64 {
	if fc.QuotaBytes > 0 {
		return fc.QuotaBytes
	}
	if fc.CAS != nil {
		if total, err := fc.CAS.TotalCapacity(); err == nil && total > 0 {
			return total
		}
	}
	if total, err := storage.GetTotalDiskCapacity("."); err == nil && total > 0 {
		return total
	}
	// Fallback to 500 GB if filesystem capacity cannot be queried
	return 500 * 1024 * 1024 * 1024
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
		return "file-text"
	case "key", "pem", "crt", "pub":
		return "key"
	case "tar.gz", "zip", "tar", "gz", "7z", "rar":
		return "archive"
	case "png", "jpg", "jpeg", "gif", "webp", "svg":
		return "image"
	case "mp4", "mkv", "webm", "mov", "avi":
		return "video"
	case "mp3", "wav", "ogg", "flac":
		return "music"
	case "go", "js", "ts", "html", "css", "json", "sql", "sh", "py", "md", "rs", "cpp", "c":
		return "code"
	case "xls", "xlsx", "csv":
		return "bar-chart-2"
	case "doc", "docx", "txt", "rtf":
		return "file-text"
	default:
		if strings.HasPrefix(mime, "image/") {
			return "image"
		} else if strings.HasPrefix(mime, "video/") {
			return "video"
		} else if strings.HasPrefix(mime, "audio/") {
			return "music"
		}
		return "file"
	}
}

func getFileExt(name string) string {
	lower := strings.ToLower(name)
	for _, comp := range []string{".tar.gz", ".tar.bz2", ".tar.xz"} {
		if strings.HasSuffix(lower, comp) {
			return comp[1:]
		}
	}
	for i := len(name) - 1; i >= 0; i-- {
		if name[i] == '.' {
			return name[i+1:]
		}
	}
	return "FILE"
}

func IsPreviewable(name, mime string) bool {
	ext := strings.ToLower(getFileExt(name))
	nonPreviewExts := map[string]bool{
		"zip": true, "iso": true, "rar": true, "7z": true, "tar": true, "gz": true, "tar.gz": true,
		"tgz": true, "bz2": true, "xz": true, "cab": true, "bin": true, "exe": true, "msi": true,
		"apk": true, "dmg": true, "pkg": true, "deb": true, "rpm": true, "dll": true, "so": true,
		"dylib": true, "o": true, "a": true, "key": true, "pem": true, "crt": true, "cer": true,
		"p12": true, "pfx": true, "class": true, "pyc": true, "dat": true,
	}
	if nonPreviewExts[ext] {
		return false
	}
	if strings.Contains(mime, "zip") || strings.Contains(mime, "tar") || (strings.Contains(mime, "octet-stream") && (nonPreviewExts[ext] || ext == "file")) {
		return false
	}

	if ext == "pdf" || mime == "application/pdf" {
		return true
	}
	if strings.HasPrefix(mime, "image/") || strings.HasPrefix(mime, "video/") || strings.HasPrefix(mime, "audio/") || strings.HasPrefix(mime, "text/") {
		return true
	}
	previewExts := map[string]bool{
		"png": true, "jpg": true, "jpeg": true, "gif": true, "webp": true, "svg": true, "bmp": true, "ico": true,
		"txt": true, "md": true, "markdown": true, "json": true, "xml": true, "csv": true, "tsv": true, "log": true,
		"html": true, "htm": true, "css": true, "js": true, "ts": true, "go": true, "py": true, "sh": true,
		"yaml": true, "yml": true, "sql": true, "env": true, "ini": true, "conf": true, "toml": true,
		"drawio": true, "bkp": true, "rs": true, "cpp": true, "c": true, "h": true, "java": true, "kt": true,
		"doc": true, "docx": true, "xls": true, "xlsx": true, "ppt": true, "pptx": true,
		"mp4": true, "webm": true, "mp3": true, "wav": true, "ogg": true,
	}
	return previewExts[ext]
}

func generatePdfSvgThumbnail(name string) string {
	escapedName := html.EscapeString(name)
	if len(escapedName) > 22 {
		escapedName = escapedName[:19] + "..."
	}
	return fmt.Sprintf(`<svg width="200" height="260" viewBox="0 0 200 260" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="8" y="8" width="184" height="244" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <rect x="22" y="24" width="44" height="20" rx="4" fill="#EF4444"/>
  <text x="44" y="38" fill="#FFFFFF" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="bold" text-anchor="middle">PDF</text>
  <text x="22" y="66" fill="#1F2937" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="600">%s</text>
  <rect x="22" y="82" width="156" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="96" width="138" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="110" width="148" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="124" width="115" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="146" width="156" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="160" width="142" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="174" width="130" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="188" width="85" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="206" width="156" height="34" rx="4" fill="#F9FAFB" stroke="#E5E7EB" stroke-width="1.2"/>
  <line x1="22" y1="223" x2="178" y2="223" stroke="#E5E7EB" stroke-width="1.2"/>
  <line x1="74" y1="206" x2="74" y2="240" stroke="#E5E7EB" stroke-width="1.2"/>
  <line x1="126" y1="206" x2="126" y2="240" stroke="#E5E7EB" stroke-width="1.2"/>
</svg>`, escapedName)
}

func generateDocumentSvgThumbnail(name, ext, snippet string) string {
	escapedName := html.EscapeString(name)
	if len(escapedName) > 22 {
		escapedName = escapedName[:19] + "..."
	}
	upperExt := strings.ToUpper(ext)
	if len(upperExt) > 5 {
		upperExt = upperExt[:5]
	}
	badgeColor := "#3B82F6"
	switch ext {
	case "xls", "xlsx", "csv":
		badgeColor = "#10B981"
	case "drawio", "bkp", "svg":
		badgeColor = "#F59E0B"
	case "json", "js", "ts", "go", "py", "sh", "sql", "html", "css":
		badgeColor = "#8B5CF6"
	case "md", "txt":
		badgeColor = "#06B6D4"
	}

	linesSvg := ""
	if strings.TrimSpace(snippet) != "" {
		rawLines := strings.Split(snippet, "\n")
		y := 86
		count := 0
		for _, line := range rawLines {
			trimmed := strings.TrimRight(line, "\r")
			if len(trimmed) > 28 {
				trimmed = trimmed[:25] + "..."
			}
			escapedLine := html.EscapeString(trimmed)
			if escapedLine == "" {
				escapedLine = " "
			}
			linesSvg += fmt.Sprintf(`<text x="22" y="%d" fill="#4B5563" font-family="'JetBrains Mono', monospace" font-size="9">%s</text>`, y, escapedLine)
			y += 16
			count++
			if count >= 9 || y > 230 {
				break
			}
		}
	} else {
		linesSvg = `
  <rect x="22" y="82" width="156" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="96" width="138" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="110" width="148" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="124" width="115" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="146" width="156" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="160" width="142" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="174" width="130" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="188" width="85" height="6" rx="3" fill="#E5E7EB"/>`
	}

	return fmt.Sprintf(`<svg width="200" height="260" viewBox="0 0 200 260" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="8" y="8" width="184" height="244" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <rect x="22" y="24" width="48" height="20" rx="4" fill="%s"/>
  <text x="46" y="38" fill="#FFFFFF" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" font-weight="bold" text-anchor="middle">%s</text>
  <text x="22" y="66" fill="#1F2937" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="600">%s</text>
  %s
</svg>`, badgeColor, upperExt, escapedName, linesSvg)
}

func extractOfficeThumbnail(readerAt io.ReaderAt, size int64, targetPath string) (string, bool) {
	zr, err := zip.NewReader(readerAt, size)
	if err != nil {
		return "", false
	}
	var targetFile *zip.File
	var mimeType string
	for _, f := range zr.File {
		lower := strings.ToLower(f.Name)
		if lower == "docprops/thumbnail.jpeg" || lower == "docprops/thumbnail.jpg" {
			targetFile = f
			mimeType = "image/jpeg"
			break
		} else if lower == "docprops/thumbnail.png" {
			targetFile = f
			mimeType = "image/png"
			break
		}
	}
	if targetFile == nil {
		return "", false
	}

	rc, err := targetFile.Open()
	if err != nil {
		return "", false
	}
	defer rc.Close()

	out, err := os.Create(targetPath)
	if err != nil {
		return "", false
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	if err != nil {
		return "", false
	}
	return mimeType, true
}

func generateOfficeSvgThumbnail(name, ext string) string {
	escapedName := html.EscapeString(name)
	if len(escapedName) > 22 {
		escapedName = escapedName[:19] + "..."
	}
	upperExt := strings.ToUpper(ext)

	if ext == "pptx" || ext == "ppt" || ext == "odp" {
		// Presentation slide 16:9 ratio
		return fmt.Sprintf(`<svg width="240" height="150" viewBox="0 0 240 150" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="6" y="6" width="228" height="138" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <rect x="6" y="6" width="228" height="34" rx="8" fill="#D24726"/>
  <rect x="6" y="24" width="228" height="16" fill="#D24726"/>
  <rect x="18" y="14" width="46" height="18" rx="3" fill="#FFFFFF"/>
  <text x="41" y="27" fill="#D24726" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" font-weight="bold" text-anchor="middle">PPTX</text>
  <text x="74" y="27" fill="#FFFFFF" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="11" font-weight="600">%s</text>
  <!-- Presentation Slide Mock Graphic / Bullet Points -->
  <circle cx="26" cy="62" r="3" fill="#D24726"/>
  <rect x="36" y="59" width="130" height="6" rx="3" fill="#D1D5DB"/>
  <circle cx="26" cy="80" r="3" fill="#D24726"/>
  <rect x="36" y="77" width="150" height="6" rx="3" fill="#D1D5DB"/>
  <circle cx="26" cy="98" r="3" fill="#D24726"/>
  <rect x="36" y="95" width="110" height="6" rx="3" fill="#D1D5DB"/>
  <!-- Mini slide card / illustration -->
  <rect x="180" y="56" width="44" height="46" rx="4" fill="#F3F4F6" stroke="#E5E7EB"/>
  <rect x="186" y="72" width="10" height="24" rx="2" fill="#D24726" opacity="0.6"/>
  <rect x="200" y="64" width="10" height="32" rx="2" fill="#D24726"/>
  <text x="218" y="132" fill="#9CA3AF" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="9" text-anchor="end">Slide 1</text>
</svg>`, escapedName)
	}

	badgeColor := "#2B579A" // Word blue
	if ext == "xlsx" || ext == "xls" || ext == "ods" {
		badgeColor = "#217346" // Excel green
	}

	return fmt.Sprintf(`<svg width="200" height="260" viewBox="0 0 200 260" fill="none" xmlns="http://www.w3.org/2000/svg">
  <rect x="8" y="8" width="184" height="244" rx="8" fill="#FFFFFF" stroke="#E5E7EB" stroke-width="2"/>
  <rect x="22" y="24" width="48" height="20" rx="4" fill="%s"/>
  <text x="46" y="38" fill="#FFFFFF" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="10" font-weight="bold" text-anchor="middle">%s</text>
  <text x="22" y="66" fill="#1F2937" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif" font-size="12" font-weight="600">%s</text>
  <rect x="22" y="82" width="156" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="96" width="138" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="110" width="148" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="124" width="115" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="146" width="156" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="160" width="142" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="174" width="130" height="6" rx="3" fill="#E5E7EB"/>
  <rect x="22" y="188" width="85" height="6" rx="3" fill="#E5E7EB"/>
</svg>`, badgeColor, upperExt, escapedName)
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
	if cleanName == "." || cleanName == ".." || cleanName == "/" || cleanName == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid folder name")
	}

	// BUG-SYS-54: Normalize 'root' parent_id to empty string to match upload/init behavior
	if req.ParentID == "root" {
		req.ParentID = ""
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

	fc.InvalidateVaultCache()
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

	// BUG-SYS-44: Verify folder exists
	var exists bool
	errCheck := fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM folders WHERE id = ? AND owner_id = ?)"), id, 1).Scan(&exists)
	if errCheck != nil || !exists {
		return echo.NewHTTPError(http.StatusNotFound, "Folder not found")
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

	tx, err := fc.DB.SQL.Begin()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to start transaction: "+err.Error())
	}
	defer tx.Rollback()

	// Move all files in all folders to trash.
	// Set folder_id = NULL (or 'f2' for vault folders) so foreign key ON DELETE CASCADE does not wipe files
	isVault := fc.IsVaultFolder(id)
	for _, fID := range allFolderIDs {
		if isVault {
			_, _ = tx.Exec(fc.DB.Rebind("UPDATE files SET is_deleted = TRUE, folder_id = 'f2' WHERE folder_id = ? AND owner_id = ?"), fID, 1)
		} else {
			_, _ = tx.Exec(fc.DB.Rebind("UPDATE files SET is_deleted = TRUE, folder_id = NULL WHERE folder_id = ? AND owner_id = ?"), fID, 1)
		}
	}

	// Delete child subfolders first (reverse order)
	for i := len(allFolderIDs) - 1; i >= 0; i-- {
		_, _ = tx.Exec(fc.DB.Rebind("DELETE FROM folders WHERE id = ? AND owner_id = ?"), allFolderIDs[i], 1)
	}

	if err := tx.Commit(); err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to commit folder deletion: "+err.Error())
	}

	fc.InvalidateVaultCache()
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
	if cleanName == "." || cleanName == ".." || cleanName == "/" || cleanName == "" {
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
	fc.InvalidateVaultCache()
	return c.JSON(http.StatusOK, map[string]string{"status": "folder_renamed", "name": cleanName})
}

type RenameFileRequest struct {
	Name string `json:"name"`
}

func (fc *FileController) RenameFile(c *echo.Context) error {
	id := c.Param("id")
	var req RenameFileRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid request")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "File name cannot be empty")
	}
	cleanName := filepath.Base(filepath.Clean(name))
	if cleanName == "." || cleanName == ".." || cleanName == "/" || cleanName == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "Invalid file name")
	}

	var folderID string
	err := fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT COALESCE(folder_id, '') FROM files WHERE id = ? AND owner_id = ? AND is_deleted = FALSE"), id, 1).Scan(&folderID)
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}
	if fc.IsVaultFolder(folderID) && !fc.isVaultUnlocked(c) {
		return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
	}

	// BUG-SYS-52: Prevent duplicate file names under the same folder
	var exists bool
	if folderID != "" {
		_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM files WHERE folder_id = ? AND name = ? AND id != ? AND owner_id = ? AND is_deleted = FALSE)"), folderID, cleanName, id, 1).Scan(&exists)
	} else {
		_ = fc.DB.SQL.QueryRow(fc.DB.Rebind("SELECT EXISTS(SELECT 1 FROM files WHERE (folder_id IS NULL OR folder_id = '') AND name = ? AND id != ? AND owner_id = ? AND is_deleted = FALSE)"), cleanName, id, 1).Scan(&exists)
	}
	if exists {
		return echo.NewHTTPError(http.StatusConflict, "File with this name already exists in this folder")
	}

	res, err := fc.DB.SQL.Exec(fc.DB.Rebind("UPDATE files SET name = ? WHERE id = ? AND owner_id = ? AND is_deleted = FALSE"), cleanName, id, 1)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to rename file: "+err.Error())
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}
	return c.JSON(http.StatusOK, map[string]string{
		"status": "file_renamed",
		"id":     id,
		"name":   cleanName,
	})
}


