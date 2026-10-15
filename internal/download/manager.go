package download

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"ztatic-go-framework/data"
	"ztatic-go-framework/fullstack"
	"ztatic-go-framework/internal/crypto"
	"ztatic-go-framework/internal/storage"
	"ztatic-go-framework/internal/upload"
	"ztatic-go-framework/realtime"
)

// ProgressComponent renders a Turbo Stream compatible component for real-time broadcasts.
type ProgressComponent struct {
	Percentage int64
}

func (p ProgressComponent) Render(ctx context.Context, w io.Writer) error {
	_, err := fmt.Fprintf(w, `<div class="progress-bar amber-hazard" style="width: %d%%;"></div>`, p.Percentage)
	return err
}

// DownloadManager orchestrates background direct and torrent magnet downloads.
type DownloadManager struct {
	CAS              *storage.CASEngine
	DB               *data.DBEngine
	Broker           *realtime.MemoryBroker
	TmpDir           string
	QuotaBytes       int64
	DirectDownloader *DirectDownloader
	TorrentClient    *TorrentClient

	tasks sync.Map // map[string]*DownloadTask
}

func NewDownloadManager(cas *storage.CASEngine, db *data.DBEngine, broker *realtime.MemoryBroker, tmpDir string, quotaBytes int64) (*DownloadManager, error) {
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create download tmp directory: %w", err)
	}

	return &DownloadManager{
		CAS:              cas,
		DB:               db,
		Broker:           broker,
		TmpDir:           tmpDir,
		QuotaBytes:       quotaBytes,
		DirectDownloader: NewDirectDownloader(),
		TorrentClient:    NewTorrentClient(),
	}, nil
}

// StartDownload creates and starts an asynchronous download job.
func (dm *DownloadManager) StartDownload(ctx context.Context, ownerID int, folderID string, link string, isVault bool, vaultKey []byte) (*DownloadTask, error) {
	return dm.StartDownloadWithFilename(ctx, ownerID, folderID, link, "", isVault, vaultKey)
}

// StartDownloadWithFilename creates and starts an asynchronous download job with optional custom filename override.
func (dm *DownloadManager) StartDownloadWithFilename(ctx context.Context, ownerID int, folderID string, link string, filenameOverride string, isVault bool, vaultKey []byte) (*DownloadTask, error) {
	norm := NormalizeLink(link)
	if norm == "" {
		return nil, errors.New("empty download link")
	}

	linkType, err := DetectLinkType(norm)
	if err != nil {
		return nil, err
	}

	resolved, _ := ResolveLink(norm)

	// Generate task ID
	randBytes := make([]byte, 4)
	_, _ = rand.Read(randBytes)
	taskID := fmt.Sprintf("dl_%d_%s", time.Now().Unix(), hex.EncodeToString(randBytes))

	// Determine initial filename
	initialName := "downloading_file"
	if filenameOverride != "" {
		initialName = CleanFilename(filenameOverride, "downloaded_file")
	} else if resolved != nil && resolved.Filename != "" && !strings.HasPrefix(resolved.Filename, "download_") {
		initialName = resolved.Filename
	} else if linkType == DownloadTypeMagnet {
		if mag, err := ParseMagnetURI(norm); err == nil && mag.DisplayName != "" {
			initialName = mag.DisplayName
		} else {
			initialName = "torrent_download.bin"
		}
	} else if linkType == DownloadTypeDirect {
		initialName = ParseFilenameFromHeaders("", norm)
	}

	taskCtx, cancel := context.WithCancel(context.Background())

	task := &DownloadTask{
		ID:         taskID,
		OwnerID:    ownerID,
		FolderID:   folderID,
		URL:        norm,
		Type:       linkType,
		Filename:   initialName,
		Status:     StatusDownloading,
		StatusText: "Menghubungkan...",
		SpeedText:  "Menghubungkan...",
		Progress:   5,
		CreatedAt:  time.Now(),
		CancelFunc: cancel,
	}

	dm.tasks.Store(taskID, task)

	// Execute download in background goroutine
	hasCustomName := filenameOverride != ""
	go dm.executeDownload(taskCtx, task, isVault, vaultKey, hasCustomName)

	return task.Snapshot(), nil
}

// StartBatchDownload creates and starts multiple download jobs.
func (dm *DownloadManager) StartBatchDownload(ctx context.Context, ownerID int, folderID string, links []string, isVault bool, vaultKey []byte) ([]*DownloadTask, error) {
	var created []*DownloadTask
	for _, l := range links {
		t, err := dm.StartDownload(ctx, ownerID, folderID, l, isVault, vaultKey)
		if err == nil {
			created = append(created, t)
		}
	}
	if len(created) == 0 {
		return nil, errors.New("no download tasks could be started")
	}
	return created, nil
}

func (dm *DownloadManager) executeDownload(ctx context.Context, task *DownloadTask, isVault bool, vaultKey []byte, hasCustomName bool) {
	tempPath := filepath.Join(dm.TmpDir, fmt.Sprintf("hornetz_dl_%s.tmp", task.ID))
	defer func() {
		// Clean up partial temp file on failure or exit
		task.Mu.RLock()
		status := task.Status
		task.Mu.RUnlock()
		if status != StatusCompleted {
			_ = os.Remove(tempPath)
		}
	}()

	f, err := os.OpenFile(tempPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		dm.failTask(task, fmt.Sprintf("failed to create temporary file: %v", err))
		return
	}
	defer f.Close()

	bufWriter := bufio.NewWriterSize(f, 2*1024*1024)
	defer bufWriter.Flush()

	// Encryption key handling
	var vk []byte
	if isVault {
		if len(vaultKey) > 0 && !bytesEqual(vaultKey, crypto.GetStandardStorageKey()) {
			vk = vaultKey
		} else {
			dm.failTask(task, "Vault locked. Master password required to download into vault folder.")
			return
		}
	} else {
		vk = crypto.GetStandardStorageKey()
	}

	encStream, err := crypto.NewEncryptStream(bufWriter, vk)
	if err != nil {
		dm.failTask(task, fmt.Sprintf("failed to initialize encryption stream: %v", err))
		return
	}

	hasher := sha256.New()
	multiDest := io.MultiWriter(encStream, hasher)

	currentUsed := dm.getUserStorageUsed(task.OwnerID)
	if dm.QuotaBytes > 0 && currentUsed >= dm.QuotaBytes {
		dm.failTask(task, "Kapasitas penyimpanan terlampaui (Storage quota exceeded)")
		return
	}

	onProgress := func(downloaded int64, total int64, speed string) {
		if dm.QuotaBytes > 0 && (currentUsed+downloaded) > dm.QuotaBytes {
			task.Mu.Lock()
			if task.CancelFunc != nil {
				task.CancelFunc()
			}
			task.Mu.Unlock()
			dm.failTask(task, "Kapasitas penyimpanan terlampaui (Storage quota exceeded)")
			return
		}

		task.Mu.Lock()
		task.DownloadedBytes = downloaded
		task.TotalBytes = total
		task.SpeedText = speed
		task.StatusText = "Mengunduh..."
		if total > 0 {
			calc := int((float64(downloaded) / float64(total)) * 90)
			if calc > 92 {
				calc = 92
			}
			task.Progress = 5 + calc
		} else {
			// Indeterminate progress (e.g. chunked transfer)
			task.Progress = 45
		}
		task.Mu.Unlock()

		if dm.Broker != nil {
			_ = dm.Broker.Publish(ctx, "nest:user_1", fullstack.TurboStreamItem{
				Action:    fullstack.StreamUpdate,
				Target:    "storage-refresh",
				Component: ProgressComponent{Percentage: int64(task.Progress)},
			})
		}
	}

	var detectedMime string
	var finalFilename string

	if task.Type == DownloadTypeDirect {
		fileInfo, err := dm.DirectDownloader.DownloadDirect(ctx, task.URL, multiDest, onProgress)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				dm.cancelTask(task)
			} else {
				dm.failTask(task, fmt.Sprintf("Direct download failed: %v", err))
			}
			return
		}
		if hasCustomName && task.Filename != "" {
			finalFilename = task.Filename
		} else {
			finalFilename = fileInfo.Filename
		}
		detectedMime = fileInfo.MimeType
		task.Mu.Lock()
		task.TotalBytes = fileInfo.TotalBytes
		task.Mu.Unlock()
	} else if task.Type == DownloadTypeMagnet {
		magInfo, err := ParseMagnetURI(task.URL)
		if err != nil {
			dm.failTask(task, fmt.Sprintf("Invalid magnet link: %v", err))
			return
		}
		finalFilename = magInfo.DisplayName

		err = dm.TorrentClient.DownloadTorrent(ctx, magInfo, multiDest, onProgress)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) {
				dm.cancelTask(task)
			} else {
				dm.failTask(task, fmt.Sprintf("Torrent download failed: %v", err))
			}
			return
		}

		// Sniff MIME type from filename extension
		ext := filepath.Ext(finalFilename)
		detectedMime = mime.TypeByExtension(ext)
		if detectedMime == "" {
			detectedMime = "application/octet-stream"
		}
	}

	// Finalize streams and flush to disk
	_ = bufWriter.Flush()
	_ = f.Close()

	task.Mu.Lock()
	task.StatusText = "Menyimpan ke CAS..."
	task.Progress = 95
	task.Filename = finalFilename
	task.MimeType = detectedMime
	task.Mu.Unlock()

	plaintextHash := hex.EncodeToString(hasher.Sum(nil))

	// Move to CAS
	casHash, existedBefore, err := dm.CAS.MoveToCASWithStatus(tempPath)
	if err != nil {
		dm.failTask(task, fmt.Sprintf("Failed to store encrypted payload in CAS: %v", err))
		return
	}

	// Insert into DB files table
	fileID := fmt.Sprintf("file_%d_%s", time.Now().Unix(), upload.GenerateID()[:8])
	if dm.DB != nil && dm.DB.SQL != nil {
		var dbFolder interface{} = nil
		if task.FolderID != "" && task.FolderID != "root" {
			dbFolder = task.FolderID
		}

		query := dm.DB.Rebind("INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash, plaintext_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
		_, err := dm.DB.SQL.Exec(query, fileID, task.OwnerID, dbFolder, finalFilename, detectedMime, task.DownloadedBytes, casHash, plaintextHash)
		if err != nil {
			if !existedBefore {
				_ = os.Remove(dm.CAS.Path(casHash))
			}
			dm.failTask(task, fmt.Sprintf("Failed to record downloaded file in database: %v", err))
			return
		}
	}

	// Mark Task Completed
	task.Mu.Lock()
	task.Status = StatusCompleted
	task.StatusText = "Selesai"
	task.SpeedText = "Idle"
	task.Progress = 100
	task.FileID = fileID
	task.CasHash = casHash
	task.PlaintextHash = plaintextHash
	task.CompletedAt = time.Now()
	task.Mu.Unlock()

	if dm.Broker != nil {
		_ = dm.Broker.Publish(context.Background(), "nest:user_1", fullstack.TurboStreamItem{
			Action:    fullstack.StreamUpdate,
			Target:    "storage-refresh",
			Component: ProgressComponent{Percentage: 100},
		})
	}
}

func (dm *DownloadManager) failTask(task *DownloadTask, msg string) {
	task.Mu.Lock()
	task.Status = StatusFailed
	task.StatusText = "Gagal"
	task.SpeedText = "Gagal"
	task.ErrorMessage = msg
	task.Progress = 0
	task.CompletedAt = time.Now()
	task.Mu.Unlock()
}

func (dm *DownloadManager) cancelTask(task *DownloadTask) {
	task.Mu.Lock()
	task.Status = StatusCancelled
	task.StatusText = "Dibatalkan"
	task.SpeedText = "Dibatalkan"
	task.Progress = 0
	task.CompletedAt = time.Now()
	task.Mu.Unlock()
}

// GetTask returns the snapshot of a specific download task if found.
func (dm *DownloadManager) GetTask(id string) (*DownloadTask, bool) {
	if val, ok := dm.tasks.Load(id); ok {
		if t, ok := val.(*DownloadTask); ok {
			return t.Snapshot(), true
		}
	}
	return nil, false
}

// CancelTask cancels an ongoing download by task ID.
func (dm *DownloadManager) CancelTask(id string) bool {
	if val, ok := dm.tasks.Load(id); ok {
		if t, ok := val.(*DownloadTask); ok {
			t.Mu.Lock()
			if t.Status == StatusCompleted {
				t.Mu.Unlock()
				return false
			}
			if t.CancelFunc != nil {
				t.CancelFunc()
			}
			t.Status = StatusCancelled
			t.StatusText = "Dibatalkan"
			t.SpeedText = "Dibatalkan"
			t.Progress = 0
			t.CompletedAt = time.Now()
			t.Mu.Unlock()
			return true
		}
	}
	return false
}

func (dm *DownloadManager) getUserStorageUsed(ownerID int) int64 {
	if dm.DB == nil || dm.DB.SQL == nil {
		return 0
	}
	var used int64
	query := dm.DB.Rebind("SELECT COALESCE(SUM(size), 0) FROM files WHERE owner_id = ? AND is_deleted = 0")
	_ = dm.DB.SQL.QueryRow(query, ownerID).Scan(&used)
	return used
}

// ListTasks returns all tasks for an owner.
func (dm *DownloadManager) ListTasks(ownerID int) []*DownloadTask {
	var list []*DownloadTask
	dm.tasks.Range(func(key, value interface{}) bool {
		if t, ok := value.(*DownloadTask); ok {
			snap := t.Snapshot()
			if snap.OwnerID == ownerID {
				list = append(list, snap)
			}
		}
		return true
	})
	return list
}

// PruneOldTasks removes finished tasks older than ttl.
func (dm *DownloadManager) PruneOldTasks(ttl time.Duration) {
	now := time.Now()
	dm.tasks.Range(func(key, value interface{}) bool {
		if t, ok := value.(*DownloadTask); ok {
			t.Mu.RLock()
			status := t.Status
			completedAt := t.CompletedAt
			t.Mu.RUnlock()

			if status == StatusCompleted || status == StatusFailed || status == StatusCancelled {
				if !completedAt.IsZero() && now.Sub(completedAt) > ttl {
					dm.tasks.Delete(key)
				}
			}
		}
		return true
	})
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
