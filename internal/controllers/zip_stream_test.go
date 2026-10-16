package controllers

import (
	"archive/zip"
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"ztatic-go-framework/data"
	"ztatic-go-framework/internal/auth"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"
)

func setupTestDBAndCAS(t *testing.T) (*data.DBEngine, *storage.CASEngine, *FileController) {
	t.Helper()

	dbEngine, err := data.NewDBEngine("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("Failed to create memory DB: %v", err)
	}

	_, err = dbEngine.SQL.Exec(`
		CREATE TABLE users (
			id INTEGER PRIMARY KEY,
			email TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL,
			salt BLOB NOT NULL,
			encrypted_vault_key BLOB NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE folders (
			id TEXT PRIMARY KEY,
			owner_id INTEGER NOT NULL,
			parent_id TEXT,
			name TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
		CREATE TABLE files (
			id TEXT PRIMARY KEY,
			owner_id INTEGER NOT NULL,
			folder_id TEXT,
			name TEXT NOT NULL,
			mime_type TEXT NOT NULL,
			size BIGINT NOT NULL,
			cas_hash TEXT NOT NULL,
			plaintext_hash TEXT DEFAULT '',
			encrypted_metadata BLOB,
			is_starred BOOLEAN DEFAULT FALSE,
			is_deleted BOOLEAN DEFAULT FALSE,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		);
	`)
	if err != nil {
		t.Fatalf("Migration failed: %v", err)
	}

	casDir := t.TempDir()
	casEngine, err := storage.NewCASEngine(casDir)
	if err != nil {
		t.Fatalf("NewCASEngine failed: %v", err)
	}

	fileCtrl := &FileController{
		DB:  dbEngine,
		CAS: casEngine,
	}

	return dbEngine, casEngine, fileCtrl
}

// createEncryptedCASFile writes plaintext to CAS encrypted with the standard or vault key.
func createEncryptedCASFile(t *testing.T, cas *storage.CASEngine, key []byte, content []byte) string {
	t.Helper()
	tempFile, err := os.CreateTemp("", "cas_enc_test_*.bin")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	encWriter, err := crypto.NewEncryptStream(tempFile, key)
	if err != nil {
		t.Fatalf("Failed to create encrypt stream: %v", err)
	}
	if _, err := encWriter.Write(content); err != nil {
		t.Fatalf("Failed to write encrypted data: %v", err)
	}
	_ = tempFile.Close()

	hash, err := cas.MoveToCAS(tempFile.Name())
	if err != nil {
		t.Fatalf("Failed to move to CAS: %v", err)
	}
	return hash
}

func TestFileController_DownloadFolder_Success(t *testing.T) {
	dbEngine, casEngine, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	// Seed user 1
	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'user1@hornetz.io', 'hash', X'00', X'00')")

	// Seed Folder structure:
	// Projects (f_proj)
	// ├── readme.txt (file_1)
	// ├── Docs (f_docs)
	// │   └── spec.txt (file_2)
	// └── EmptyFolder (f_empty)
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_proj', 1, NULL, 'Projects')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_docs', 1, 'f_proj', 'Docs')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_empty', 1, 'f_proj', 'EmptyFolder')")

	// Files
	stdKey := crypto.GetStandardStorageKey()
	readmeContent := []byte("This is the Projects README.")
	readmeHash := createEncryptedCASFile(t, casEngine, stdKey, readmeContent)

	specContent := []byte("System Specification v1.0")
	specHash := createEncryptedCASFile(t, casEngine, stdKey, specContent)

	createdAt := "2026-05-10T12:00:00Z"
	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, created_at, is_deleted)
		VALUES ('file_1', 1, 'f_proj', 'readme.txt', 'text/plain', ?, ?, ?, FALSE)`, len(readmeContent), readmeHash, createdAt)
	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, created_at, is_deleted)
		VALUES ('file_2', 1, 'f_docs', 'spec.txt', 'text/plain', ?, ?, ?, FALSE)`, len(specContent), specHash, createdAt)

	// Deleted file (must NOT be included in zip)
	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted)
		VALUES ('file_del', 1, 'f_proj', 'deleted.txt', 'text/plain', 100, 'dummy', TRUE)`)

	e := echo.New()
	e.GET("/api/folders/:id/download", fileCtrl.DownloadFolder)

	req := httptest.NewRequest(http.MethodGet, "/api/folders/f_proj/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", rec.Code, rec.Body.String())
	}

	if ct := rec.Header().Get("Content-Type"); ct != "application/zip" {
		t.Errorf("Expected Content-Type application/zip, got %q", ct)
	}

	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, `filename="Projects.zip"`) {
		t.Errorf("Expected Content-Disposition with Projects.zip, got %q", cd)
	}

	// Verify ZIP archive contents using archive/zip.Reader
	bodyBytes := rec.Body.Bytes()
	zipReader, err := zip.NewReader(bytes.NewReader(bodyBytes), int64(len(bodyBytes)))
	if err != nil {
		t.Fatalf("Failed to parse returned ZIP archive: %v", err)
	}

	entries := make(map[string]*zip.File)
	for _, f := range zipReader.File {
		entries[f.Name] = f
	}

	// 1. Verify root directory entry
	if _, ok := entries["Projects/"]; !ok {
		t.Errorf("Missing root directory entry 'Projects/'")
	}

	// 2. Verify subfolder directory entries
	if _, ok := entries["Projects/Docs/"]; !ok {
		t.Errorf("Missing directory entry 'Projects/Docs/'")
	}
	if _, ok := entries["Projects/EmptyFolder/"]; !ok {
		t.Errorf("Missing empty directory entry 'Projects/EmptyFolder/'")
	}

	// 3. Verify file entries and contents
	readmeEntry, ok := entries["Projects/readme.txt"]
	if !ok {
		t.Fatalf("Missing file entry 'Projects/readme.txt'")
	}
	rFile, err := readmeEntry.Open()
	if err != nil {
		t.Fatalf("Failed to open readme.txt entry: %v", err)
	}
	defer rFile.Close()
	readBytes, _ := io.ReadAll(rFile)
	if !bytes.Equal(readBytes, readmeContent) {
		t.Errorf("Decrypted readme.txt content mismatch: got %q, want %q", string(readBytes), string(readmeContent))
	}

	specEntry, ok := entries["Projects/Docs/spec.txt"]
	if !ok {
		t.Fatalf("Missing file entry 'Projects/Docs/spec.txt'")
	}
	sFile, err := specEntry.Open()
	if err != nil {
		t.Fatalf("Failed to open spec.txt entry: %v", err)
	}
	defer sFile.Close()
	specReadBytes, _ := io.ReadAll(sFile)
	if !bytes.Equal(specReadBytes, specContent) {
		t.Errorf("Decrypted spec.txt content mismatch: got %q, want %q", string(specReadBytes), string(specContent))
	}

	// 4. Verify deleted file was NOT included
	if _, ok := entries["Projects/deleted.txt"]; ok {
		t.Errorf("Deleted file 'Projects/deleted.txt' should not be in the ZIP")
	}
}

func TestFileController_DownloadFolder_VaultSecurity(t *testing.T) {
	dbEngine, casEngine, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'vault@hornetz.io', 'hash', X'00', X'00')")
	// f2 is standard root vault folder
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f2', 1, NULL, 'Vault Root')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_vault_sub', 1, 'f2', 'Secret Cell')")

	vaultKey := []byte("vaultsecretkey1234567890abcdef12")
	secretData := []byte("TOP SECRET FINANCIAL DATA")
	secHash := createEncryptedCASFile(t, casEngine, vaultKey, secretData)

	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted)
		VALUES ('v_file_1', 1, 'f_vault_sub', 'passwords.txt', 'text/plain', ?, ?, FALSE)`, len(secretData), secHash)

	e := echo.New()
	e.GET("/api/folders/:id/download", fileCtrl.DownloadFolder)

	// 1. Unauthenticated / locked vault request must return 401 Unauthorized
	reqLocked := httptest.NewRequest(http.MethodGet, "/api/folders/f_vault_sub/download", nil)
	recLocked := httptest.NewRecorder()
	e.ServeHTTP(recLocked, reqLocked)

	if recLocked.Code != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for locked vault folder download, got %d: %s", recLocked.Code, recLocked.Body.String())
	}

	// 2. Authenticated vault request with active session
	auth.GlobalSessionStore.SetKey("valid_vault_session", vaultKey)
	defer auth.GlobalSessionStore.DeleteKey("valid_vault_session")

	reqUnlocked := httptest.NewRequest(http.MethodGet, "/api/folders/f_vault_sub/download", nil)
	reqUnlocked.AddCookie(&http.Cookie{Name: "swarm_session", Value: "valid_vault_session"})
	recUnlocked := httptest.NewRecorder()
	e.ServeHTTP(recUnlocked, reqUnlocked)

	if recUnlocked.Code != http.StatusOK {
		t.Fatalf("Expected status 200, got %d: %s", recUnlocked.Code, recUnlocked.Body.String())
	}

	// Verify Cache-Control header has private, no-store, no-cache
	cc := recUnlocked.Header().Get("Cache-Control")
	if !strings.Contains(cc, "no-store") {
		t.Errorf("Expected Cache-Control to contain 'no-store' for Vault folder, got %q", cc)
	}

	// Verify ZIP can be read and decrypted content matches
	zipReader, err := zip.NewReader(bytes.NewReader(recUnlocked.Body.Bytes()), int64(recUnlocked.Body.Len()))
	if err != nil {
		t.Fatalf("Failed to parse returned vault ZIP: %v", err)
	}

	var foundSecret bool
	for _, f := range zipReader.File {
		if strings.HasSuffix(f.Name, "passwords.txt") {
			foundSecret = true
			rc, err := f.Open()
			if err != nil {
				t.Fatalf("Failed to open passwords.txt in zip: %v", err)
			}
			defer rc.Close()
			decBytes, _ := io.ReadAll(rc)
			if !bytes.Equal(decBytes, secretData) {
				t.Errorf("Decrypted vault content mismatch: got %q, want %q", string(decBytes), string(secretData))
			}
		}
	}
	if !foundSecret {
		t.Errorf("passwords.txt was not found in vault zip")
	}
}

func TestFileController_DownloadFolder_IDOR_Blocked(t *testing.T) {
	dbEngine, _, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	// Seed user 1 and user 2
	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'user1@hornetz.io', 'hash', X'00', X'00')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (2, 'user2@hornetz.io', 'hash', X'00', X'00')")

	// User 2 owns folder
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_user2', 2, NULL, 'Private User 2')")

	e := echo.New()
	e.GET("/api/folders/:id/download", fileCtrl.DownloadFolder)

	// User 1 requests User 2's folder (default auth context userID is 1)
	req := httptest.NewRequest(http.MethodGet, "/api/folders/f_user2/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Expected 404 Not Found for IDOR folder download, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFileController_DownloadFolder_NotFound(t *testing.T) {
	dbEngine, _, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	e := echo.New()
	e.GET("/api/folders/:id/download", fileCtrl.DownloadFolder)

	req := httptest.NewRequest(http.MethodGet, "/api/folders/nonexistent_folder/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("Expected 404 Not Found, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestFileController_DownloadFolder_HEAD(t *testing.T) {
	dbEngine, _, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'user1@hornetz.io', 'hash', X'00', X'00')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_head', 1, NULL, 'Head Test')")

	e := echo.New()
	e.HEAD("/api/folders/:id/download", fileCtrl.DownloadFolder)

	req := httptest.NewRequest(http.MethodHead, "/api/folders/f_head/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("Expected 200 OK for HEAD, got %d", rec.Code)
	}
	if rec.Header().Get("Content-Type") != "application/zip" {
		t.Errorf("Expected Content-Type application/zip, got %q", rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Content-Disposition"), "Head_Test.zip") {
		t.Errorf("Expected Content-Disposition to contain Head_Test.zip, got %q", rec.Header().Get("Content-Disposition"))
	}
	if rec.Body.Len() != 0 {
		t.Errorf("HEAD request should have empty body, got %d bytes", rec.Body.Len())
	}
}

func TestFileController_DownloadFolder_StoreVsDeflate(t *testing.T) {
	dbEngine, casEngine, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'user1@hornetz.io', 'hash', X'00', X'00')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_comp', 1, NULL, 'Compression')")

	stdKey := crypto.GetStandardStorageKey()
	mp4Hash := createEncryptedCASFile(t, casEngine, stdKey, []byte("fake video data"))
	txtHash := createEncryptedCASFile(t, casEngine, stdKey, []byte("plain text compressible data"))

	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted)
		VALUES ('file_mp4', 1, 'f_comp', 'clip.mp4', 'video/mp4', 15, ?, FALSE)`, mp4Hash)
	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted)
		VALUES ('file_txt', 1, 'f_comp', 'notes.txt', 'text/plain', 28, ?, FALSE)`, txtHash)

	e := echo.New()
	e.GET("/api/folders/:id/download", fileCtrl.DownloadFolder)

	req := httptest.NewRequest(http.MethodGet, "/api/folders/f_comp/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DownloadFolder failed: %d - %s", rec.Code, rec.Body.String())
	}

	zipReader, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("Failed to parse zip: %v", err)
	}

	for _, f := range zipReader.File {
		if strings.HasSuffix(f.Name, "clip.mp4") {
			if f.Method != zip.Store {
				t.Errorf("Expected clip.mp4 to use zip.Store (0), got %d", f.Method)
			}
		} else if strings.HasSuffix(f.Name, "notes.txt") {
			if f.Method != zip.Deflate {
				t.Errorf("Expected notes.txt to use zip.Deflate (8), got %d", f.Method)
			}
		}
	}
}

func TestFileController_DownloadFolder_DuplicateFilenames(t *testing.T) {
	dbEngine, casEngine, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'user1@hornetz.io', 'hash', X'00', X'00')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_dup', 1, NULL, 'DuplicateTest')")

	stdKey := crypto.GetStandardStorageKey()
	hash1 := createEncryptedCASFile(t, casEngine, stdKey, []byte("Content 1"))
	hash2 := createEncryptedCASFile(t, casEngine, stdKey, []byte("Content 2"))

	// Two files with the exact same name in the same folder
	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted)
		VALUES ('dup_1', 1, 'f_dup', 'report.pdf', 'application/pdf', 9, ?, FALSE)`, hash1)
	_, _ = dbEngine.SQL.Exec(`INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, is_deleted)
		VALUES ('dup_2', 1, 'f_dup', 'report.pdf', 'application/pdf', 9, ?, FALSE)`, hash2)

	e := echo.New()
	e.GET("/api/folders/:id/download", fileCtrl.DownloadFolder)

	req := httptest.NewRequest(http.MethodGet, "/api/folders/f_dup/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("DownloadFolder failed: %d - %s", rec.Code, rec.Body.String())
	}

	zipReader, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("Failed to parse zip: %v", err)
	}

	names := make(map[string]bool)
	for _, f := range zipReader.File {
		names[f.Name] = true
	}

	if !names["DuplicateTest/report.pdf"] {
		t.Errorf("Expected 'DuplicateTest/report.pdf' in zip")
	}
	if !names["DuplicateTest/report (1).pdf"] {
		t.Errorf("Expected disambiguated 'DuplicateTest/report (1).pdf' in zip")
	}
}

func TestFileController_DownloadFolder_EmptyFolder(t *testing.T) {
	dbEngine, _, fileCtrl := setupTestDBAndCAS(t)
	defer dbEngine.Close()

	_, _ = dbEngine.SQL.Exec("INSERT INTO users (id, email, password_hash, salt, encrypted_vault_key) VALUES (1, 'user1@hornetz.io', 'hash', X'00', X'00')")
	_, _ = dbEngine.SQL.Exec("INSERT INTO folders (id, owner_id, parent_id, name) VALUES ('f_solitary', 1, NULL, 'EmptySingle')")

	e := echo.New()
	e.GET("/api/folders/:id/download", fileCtrl.DownloadFolder)

	req := httptest.NewRequest(http.MethodGet, "/api/folders/f_solitary/download", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("Expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	zipReader, err := zip.NewReader(bytes.NewReader(rec.Body.Bytes()), int64(rec.Body.Len()))
	if err != nil {
		t.Fatalf("Failed to parse zip: %v", err)
	}

	if len(zipReader.File) != 1 {
		t.Fatalf("Expected exactly 1 directory entry for empty folder, got %d", len(zipReader.File))
	}
	if zipReader.File[0].Name != "EmptySingle/" {
		t.Errorf("Expected entry name 'EmptySingle/', got %q", zipReader.File[0].Name)
	}
}
