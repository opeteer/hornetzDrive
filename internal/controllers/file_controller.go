package controllers

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"ztatic-go-framework/data"
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

// SeedInitialData populates database with initial real data if empty
func (fc *FileController) SeedInitialData() {
	var count int
	_ = fc.DB.SQL.QueryRow("SELECT COUNT(*) FROM files").Scan(&count)
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
	fc.DB.SQL.Exec(ignoreClause + ` INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES
		('file_1', 1, 'f1', 'laporan_keuangan_q3_2026.pdf', 'application/pdf', 25690112, 'a8f3b2c91d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567'),
		('file_2', 1, 'f2', 'kunci_akses_master_vault.key', 'application/octet-stream', 4300, 'f9e8d7c6b5a432109876543210fedcba9876543210fedcba9876543210fedcba'),
		('file_3', 1, 'f3', 'hornetz_system_architecture.pdf', 'application/pdf', 19084000, '1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef'),
		('file_4', 1, 'f3', 'cadangan_basis_data_swarm.tar.gz', 'application/gzip', 1503238553, '7766554433221100998877665544332211009988776655443322110099887766')` + onConflict)
}

func (fc *FileController) GetFiles(c *echo.Context) error {
	fc.SeedInitialData()

	tab := c.QueryParam("tab")
	search := c.QueryParam("q")
	folderID := c.QueryParam("folder_id")

	query := "SELECT id, owner_id, COALESCE(folder_id, ''), name, mime_type, size, cas_hash, created_at FROM files WHERE 1=1"
	args := []interface{}{}

	if folderID != "" {
		query += " AND folder_id = ?"
		args = append(args, folderID)
	} else if tab == "vault" {
		query += " AND (folder_id = 'f2' OR mime_type = 'application/octet-stream' OR name LIKE '%.key')"
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
		if err := rows.Scan(&f.ID, &f.OwnerID, &f.FolderID, &f.Name, &f.MimeType, &f.Size, &f.CasHash, &f.CreatedAt); err == nil {
			f.Icon = getFileIcon(f.Name, f.MimeType)
			f.Ext = getFileExt(f.Name)
			files = append(files, f)
		}
	}

	// Filter tabs simulation if requested
	if tab == "starred" {
		files = files[:min(len(files), 2)]
	} else if tab == "trash" {
		files = []FileRecord{}
	}

	return c.JSON(http.StatusOK, files)
}

func (fc *FileController) GetFolders(c *echo.Context) error {
	fc.SeedInitialData()

	rows, err := fc.DB.SQL.Query(`
		SELECT f.id, f.owner_id, COALESCE(f.parent_id, ''), f.name, COUNT(fi.id) as file_count, f.created_at 
		FROM folders f 
		LEFT JOIN files fi ON fi.folder_id = f.id 
		GROUP BY f.id`)
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
	query := fc.DB.Rebind("SELECT id, name, mime_type, cas_hash FROM files WHERE id = ?")
	err := fc.DB.SQL.QueryRow(query, id).Scan(&f.ID, &f.Name, &f.MimeType, &f.CasHash)
	if err == sql.ErrNoRows {
		return echo.NewHTTPError(http.StatusNotFound, "File not found")
	}

	path := fc.CAS.Path(f.CasHash)
	file, err := os.Open(path)
	if err != nil {
		// Fallback for mock files
		c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", f.Name))
		return c.String(http.StatusOK, "Decrypted Content of "+f.Name)
	}
	defer file.Close()

	vk := crypto.DummyVK()
	decStream, err := crypto.NewDecryptStream(file, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Decryption error")
	}

	c.Response().Header().Set("Content-Type", f.MimeType)
	c.Response().Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", f.Name))
	_, err = io.Copy(c.Response(), decStream)
	return err
}

func (fc *FileController) DeleteFile(c *echo.Context) error {
	id := c.Param("id")
	query := fc.DB.Rebind("DELETE FROM files WHERE id = ?")
	_, err := fc.DB.SQL.Exec(query, id)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "Failed to delete file: "+err.Error())
	}
	return c.JSON(http.StatusOK, map[string]string{"status": "deleted"})
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
