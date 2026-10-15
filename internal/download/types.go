package download

import (
	"context"
	"sync"
	"time"
)

// DownloadType represents the origin protocol of the download link.
type DownloadType string

const (
	DownloadTypeDirect DownloadType = "direct"
	DownloadTypeMagnet DownloadType = "magnet"
)

// DownloadStatus represents the current lifecycle state of a download task.
type DownloadStatus string

const (
	StatusPending     DownloadStatus = "pending"
	StatusDownloading DownloadStatus = "downloading"
	StatusCompleted   DownloadStatus = "completed"
	StatusFailed      DownloadStatus = "failed"
	StatusCancelled   DownloadStatus = "cancelled"
)

// DownloadTask represents an in-flight or completed download job.
type DownloadTask struct {
	ID              string         `json:"id"`
	OwnerID         int            `json:"owner_id"`
	FolderID        string         `json:"folder_id"`
	URL             string         `json:"url"`
	Type            DownloadType   `json:"type"`
	Filename        string         `json:"filename"`
	MimeType        string         `json:"mime_type"`
	TotalBytes      int64          `json:"total_bytes"`
	DownloadedBytes int64          `json:"downloaded_bytes"`
	Progress        int            `json:"progress"` // 0 - 100
	SpeedText       string         `json:"speed_text"`
	Status          DownloadStatus `json:"status"`
	StatusText      string         `json:"status_text"`
	ErrorMessage    string         `json:"error_message,omitempty"`
	FileID          string         `json:"file_id,omitempty"`
	CasHash         string         `json:"cas_hash,omitempty"`
	PlaintextHash   string         `json:"plaintext_hash,omitempty"`
	ActiveThreads   int            `json:"active_threads,omitempty"`
	CompletedBlocks int            `json:"completed_blocks,omitempty"`
	TotalBlocks     int            `json:"total_blocks,omitempty"`
	IsAccelerated   bool           `json:"is_accelerated,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	CompletedAt     time.Time      `json:"completed_at,omitempty"`

	Mu         sync.RWMutex       `json:"-"`
	CancelFunc context.CancelFunc `json:"-"`
}

// Snapshot returns a pointer to a copied task without copying the mutex.
func (t *DownloadTask) Snapshot() *DownloadTask {
	t.Mu.RLock()
	defer t.Mu.RUnlock()
	return &DownloadTask{
		ID:              t.ID,
		OwnerID:         t.OwnerID,
		FolderID:        t.FolderID,
		URL:             t.URL,
		Type:            t.Type,
		Filename:        t.Filename,
		MimeType:        t.MimeType,
		TotalBytes:      t.TotalBytes,
		DownloadedBytes: t.DownloadedBytes,
		Progress:        t.Progress,
		SpeedText:       t.SpeedText,
		Status:          t.Status,
		StatusText:      t.StatusText,
		ErrorMessage:    t.ErrorMessage,
		FileID:          t.FileID,
		CasHash:         t.CasHash,
		PlaintextHash:   t.PlaintextHash,
		ActiveThreads:   t.ActiveThreads,
		CompletedBlocks: t.CompletedBlocks,
		TotalBlocks:     t.TotalBlocks,
		IsAccelerated:   t.IsAccelerated,
		CreatedAt:       t.CreatedAt,
		CompletedAt:     t.CompletedAt,
	}
}
