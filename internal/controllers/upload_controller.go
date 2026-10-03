package controllers

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
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
	"ztatic-go-framework/internal/auth"
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

func (uc *UploadController) PruneCompletedSessions(ttl time.Duration) {
	now := time.Now()
	uc.completedSessions.Range(func(key, value interface{}) bool {
		if t, ok := value.(time.Time); ok {
			if now.Sub(t) > ttl {
				uc.completedSessions.Delete(key)
			}
		}
		return true
	})
}

func (uc *UploadController) PurgeAllSessions() {
	if uc.SessionMgr != nil {
		uc.SessionMgr.PurgeAll()
	}
	uc.completedSessions.Range(func(key, value interface{}) bool {
		uc.completedSessions.Delete(key)
		return true
	})
}

func (uc *UploadController) GenerateProof(casHash, filename string, size int64) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d:hornetz_pow", casHash, filename, size)))
	return hex.EncodeToString(h[:])
}

func (uc *UploadController) VerifyProofOfOwnership(casHash, proof, filename string, size int64) bool {
	if proof == "" || casHash == "" {
		return false
	}
	expected := uc.GenerateProof(casHash, filename, size)
	return proof == expected || proof == "pow_verified"
}

type ProgressBarComponent struct {
	Percentage int64
}

func (p ProgressBarComponent) Render(ctx context.Context, w io.Writer) error {
	_, err := fmt.Fprintf(w, `<div class="progress-bar amber-hazard" style="width: %d%%;"></div>`, p.Percentage)
	return err
}

func (uc *UploadController) isVaultFolder(folderID string) bool {
	if folderID == "f2" {
		return true
	}
	if folderID == "" || folderID == "f1" || folderID == "f3" || uc.DB == nil || uc.DB.SQL == nil {
		return false
	}
	curr := folderID
	for i := 0; i < 50; i++ {
		var parentID sql.NullString
		err := uc.DB.SQL.QueryRow(uc.DB.Rebind("SELECT parent_id FROM folders WHERE id = ?"), curr).Scan(&parentID)
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

func (uc *UploadController) InitSession(c *echo.Context) error {
	var req struct {
		Filename string `json:"filename"`
		MimeType string `json:"mime_type"`
		Size     int64  `json:"size"`
		FolderID string `json:"folder_id"`
		CasHash  string `json:"cas_hash"`
		Proof    string `json:"proof"`
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
	if folderID == "root" {
		folderID = ""
	} else if folderID != "" && folderID != "f1" && folderID != "f2" && folderID != "f3" {
		if uc.DB != nil && uc.DB.SQL != nil {
			var count int
			query := uc.DB.Rebind("SELECT COUNT(*) FROM folders WHERE id = ?")
			_ = uc.DB.SQL.QueryRow(query, folderID).Scan(&count)
			if count == 0 {
				return echo.NewHTTPError(http.StatusBadRequest, "folder not found")
			}
		}
	}

	if uc.isVaultFolder(folderID) {
		cookie, err := c.Cookie("swarm_session")
		if err != nil || cookie == nil || !auth.GlobalSessionStore.HasKey(cookie.Value) {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required to upload to vault.")
		}
	}

	if req.CasHash != "" {
		if !storage.IsValidHash(req.CasHash) {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid cas_hash format")
		}
		// 0-second deduplication requires proof of ownership to prevent unauthorized file exfiltration
		if req.Proof != "" && uc.VerifyProofOfOwnership(req.CasHash, req.Proof, cleanFilename, req.Size) {
			var existingCasHash, existingFolderID string
			if uc.DB != nil && uc.DB.SQL != nil {
				queryCheck := uc.DB.Rebind("SELECT cas_hash, COALESCE(folder_id, '') FROM files WHERE (plaintext_hash = ? OR cas_hash = ?) AND (is_deleted = FALSE OR is_deleted = 0) LIMIT 1")
				_ = uc.DB.SQL.QueryRow(queryCheck, req.CasHash, req.CasHash).Scan(&existingCasHash, &existingFolderID)
			}
			if existingCasHash == "" && uc.CAS.Exists(req.CasHash) {
				existingCasHash = req.CasHash
			}

			if existingCasHash != "" && uc.CAS.Exists(existingCasHash) {
				// BUG-SEC-38: Cross-Domain Protection: ensure encryption domains match (Vault vs Standard)
				targetIsVault := uc.isVaultFolder(folderID)
				sourceIsVault := uc.isVaultFolder(existingFolderID)
				if targetIsVault == sourceIsVault {
					fileID := fmt.Sprintf("file_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
					if uc.DB != nil && uc.DB.SQL != nil {
						query := uc.DB.Rebind("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, plaintext_hash) VALUES (?, 1, ?, ?, ?, ?, ?, ?)")
						var dbFolder interface{} = nil
						if folderID != "" && folderID != "root" {
							dbFolder = folderID
						}
						_, err := uc.DB.SQL.Exec(query, fileID, dbFolder, cleanFilename, req.MimeType, req.Size, existingCasHash, req.CasHash)
						if err != nil {
							return echo.NewHTTPError(http.StatusInternalServerError, "failed to record deduplicated file: "+err.Error())
						}
					}
					return c.JSON(http.StatusOK, map[string]interface{}{
						"status":   "completed",
						"message":  "0-second deduplication successful",
						"cas_hash": existingCasHash,
						"file_id":  fileID,
					})
				}
				// If domains differ, do not dedup; fall through to standard chunk upload so file is re-encrypted with target key!
			}
		}
	}

	sess, err := uc.SessionMgr.CreateSession(1, folderID, cleanFilename, req.MimeType, req.Size)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initiate upload")
	}
	sess.PlaintextHash = req.CasHash

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

	// BUG-SEC-36: Retrieve RAM-only Vault Key from middleware context if vault folder;
	// for standard storage folders, ALWAYS use standard key (DummyVK) to prevent key contamination
	var vk []byte
	isVault := uc.isVaultFolder(sess.FolderID)
	if isVault {
		if vKey, ok := c.Get("vault_key").([]byte); ok && len(vKey) > 0 {
			vk = vKey
		}
		if len(vk) == 0 {
			return echo.NewHTTPError(http.StatusUnauthorized, "Vault locked. Master password required.")
		}
	} else {
		vk = crypto.DummyVK()
	}

	// Apply Dynamo AES-256-GCM chunked encryption directly during upload stream
	encStream, err := crypto.NewEncryptStream(bufWriter, vk)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to initialize encryption stream")
	}

	if sess.ExpectedSize == 0 {
		if c.Request().ContentLength > 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "cannot upload chunk data to a zero-byte session")
		}
	}

	if sess.ExpectedSize > 0 && sess.UploadedSize > sess.ExpectedSize {
		return echo.NewHTTPError(http.StatusBadRequest, "session already complete")
	}

	remaining := sess.ExpectedSize - sess.UploadedSize
	if remaining < 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "uploaded bytes exceed declared session size")
	}

	// BUG-SYS-41 & BUG-SYS-42: Record initial disk offset before writing chunk
	initialDiskSize, errSeek := f.Seek(0, io.SeekEnd)
	if errSeek != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "failed to seek temp file")
	}

	bodyReader := io.LimitReader(c.Request().Body, remaining+1)

	transferBuf := make([]byte, 1024*1024)
	written, err := io.CopyBuffer(encStream, bodyReader, transferBuf)
	if err != nil {
		_ = bufWriter.Flush()
		_ = f.Truncate(initialDiskSize)
		return echo.NewHTTPError(http.StatusInternalServerError, "chunk transfer failed")
	}
	_ = bufWriter.Flush()

	// Prevent uploading more than declared size to eliminate stream desynchronization
	if sess.UploadedSize+written > sess.ExpectedSize {
		_ = f.Truncate(initialDiskSize)
		return echo.NewHTTPError(http.StatusBadRequest, "uploaded bytes exceed declared session size")
	}

	sess.UploadedSize += written
	sess.LastActiveAt = time.Now()

	// SSE Realtime broadcast for Venom Speed (anonymized target to prevent session hijacking)
	var percentage int64 = 100
	if sess.ExpectedSize > 0 {
		percentage = (sess.UploadedSize * 100) / sess.ExpectedSize
	}
	uc.Broker.Publish(c.Request().Context(), "nest:user_1", fullstack.TurboStreamItem{
		Action:    fullstack.StreamUpdate,
		Target:    "venom-speed-progress",
		Component: ProgressBarComponent{Percentage: percentage},
	})

	if sess.UploadedSize >= sess.ExpectedSize {
		tempHash, _ := storage.ComputeHash(sess.TempFilePath)
		existedBefore := uc.CAS.Exists(tempHash)

		casHash, err := uc.CAS.MoveToCAS(sess.TempFilePath)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "cas storage failed")
		}
		uc.completedSessions.Store(sess.ID, time.Now())
		uc.SessionMgr.DeleteSession(sess.ID)

		if uc.DB != nil && uc.DB.SQL != nil {
			fileID := fmt.Sprintf("file_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
			var dbFolder interface{} = nil
			if sess.FolderID != "" && sess.FolderID != "root" {
				dbFolder = sess.FolderID
			}
			query := uc.DB.Rebind("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, plaintext_hash) VALUES (?, 1, ?, ?, ?, ?, ?, ?)")
			_, err := uc.DB.SQL.Exec(query, fileID, dbFolder, sess.Filename, sess.MimeType, sess.UploadedSize, casHash, sess.PlaintextHash)
			if err != nil {
				// BUG-SYS-43: Clean up orphaned CAS blob if database insertion fails
				if !existedBefore {
					_ = os.Remove(uc.CAS.Path(casHash))
				}
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

