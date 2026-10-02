package storage

import (
	"context"
	"io"
	"time"
)

// ReadSeekCloser combines io.Reader, io.Seeker, io.Closer, and io.ReaderAt.
type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
	io.ReaderAt
}

// FileRecord represents metadata of a persisted file in the storage engine.
type FileRecord struct {
	Key          string            `json:"key"`
	OriginalName string            `json:"original_name"`
	Size         int64             `json:"size"`
	MIME         string            `json:"mime"`
	Extension    string            `json:"extension"`
	SHA256       string            `json:"sha256,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// SaveOptions specifies optional metadata when persisting a file.
type SaveOptions struct {
	OriginalName string
	MIME         string
	Extension    string
	SHA256       string
	Metadata     map[string]string
}

// URLOptions configures URL generation (presigned or public).
type URLOptions struct {
	Expiry   time.Duration
	Download bool
	Filename string
}

// Storage is the central abstraction for file persistence.
type Storage interface {
	// Save writes the incoming stream to the specified storage key.
	Save(ctx context.Context, key string, r io.Reader, size int64, opts SaveOptions) (*FileRecord, error)
	// Open retrieves a readable and seekable stream for the specified key.
	Open(ctx context.Context, key string) (ReadSeekCloser, *FileRecord, error)
	// Delete removes the file associated with the key.
	Delete(ctx context.Context, key string) error
	// Exists checks whether a file exists for the given key.
	Exists(ctx context.Context, key string) (bool, error)
	// Stat returns metadata about the file without opening the content stream.
	Stat(ctx context.Context, key string) (*FileRecord, error)
	// URL returns a public or temporary presigned URL for downloading the file.
	URL(ctx context.Context, key string, opts URLOptions) (string, error)
}
