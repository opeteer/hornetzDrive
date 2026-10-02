package upload

import (
	"time"

	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
)

// Size constants for developer ergonomics.
const (
	B  int64 = 1
	KB int64 = 1024 * B
	MB int64 = 1024 * KB
	GB int64 = 1024 * MB
)

// NamingStrategy defines how storage keys are generated for uploaded files.
type NamingStrategy int

const (
	// StrategyUUID generates a random UUIDv4 key preserving the original extension.
	StrategyUUID NamingStrategy = iota
	// StrategyULID generates a timestamp-ordered ULID-like unique key.
	StrategyULID
	// StrategySHA256 computes a SHA-256 hash of the file content for deduplication.
	StrategySHA256
	// StrategyOriginalSanitized cleans the original filename and appends a short random suffix.
	StrategyOriginalSanitized
)

// Dimensions defines image width and height constraints.
type Dimensions struct {
	MaxWidth  int
	MaxHeight int
	MinWidth  int
	MinHeight int
}

// Config defines the configuration for the upload manager.
type Config struct {
	// MaxFileSize is the maximum allowed file size in bytes (default: 10 MB).
	MaxFileSize int64
	// MinFileSize is the minimum allowed file size in bytes (default: 1 byte).
	MinFileSize int64
	// MaxMemory is the maximum memory threshold for multipart parsing before spilling to disk (default: 32 MB).
	MaxMemory int64

	// AllowedMIMEs is an allowlist of permitted MIME types (e.g., "image/jpeg", "image/png").
	AllowedMIMEs []string
	// AllowedExtensions is an allowlist of permitted file extensions (e.g., ".jpg", ".png").
	AllowedExtensions []string

	// ImageDimensions specifies image size bounds if image validation is required.
	ImageDimensions *Dimensions

	// NamingStrategy determines how keys are generated.
	NamingStrategy NamingStrategy
	// CustomNamingFunc allows developers to supply their own key generation logic.
	CustomNamingFunc func(originalFilename string, content []byte) string

	// Scanner is an optional malware/content security scanner (e.g. Heuristic, ClamAV).
	Scanner scanner.Scanner
	// FailClosedScanner determines whether a scanner timeout/error blocks the upload (default: true).
	FailClosedScanner bool

	// Storage is the target storage engine (e.g., LocalStorage, MemoryStorage).
	Storage storage.Storage

	// TempDir is the directory used for temporary file operations (empty defaults to os.TempDir()).
	TempDir string
	// UploadTimeout is the maximum duration permitted for processing an upload (default: 60s).
	UploadTimeout time.Duration
}

// DefaultConfig returns a secure, sensible default configuration.
func DefaultConfig() Config {
	return Config{
		MaxFileSize:       10 * MB,
		MinFileSize:       1 * B,
		MaxMemory:         32 * MB,
		AllowedMIMEs:      ImageMIMEs(),
		AllowedExtensions: ImageExtensions(),
		NamingStrategy:    StrategyUUID,
		FailClosedScanner: true,
		UploadTimeout:     60 * time.Second,
	}
}

// Preset helper functions for common file categories

// ImageExtensions returns commonly permitted web image file extensions.
func ImageExtensions() []string {
	return []string{".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp", ".ico"}
}

// ImageMIMEs returns commonly permitted web image MIME types.
func ImageMIMEs() []string {
	return []string{
		"image/jpeg",
		"image/png",
		"image/gif",
		"image/webp",
		"image/svg+xml",
		"image/bmp",
		"image/x-icon",
		"image/vnd.microsoft.icon",
	}
}

// DocumentExtensions returns standard document file extensions.
func DocumentExtensions() []string {
	return []string{".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".csv", ".rtf"}
}

// DocumentMIMEs returns standard document MIME types.
func DocumentMIMEs() []string {
	return []string{
		"application/pdf",
		"application/msword",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		"application/vnd.ms-excel",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		"application/vnd.ms-powerpoint",
		"application/vnd.openxmlformats-officedocument.presentationml.presentation",
		"text/plain",
		"text/csv",
		"application/rtf",
	}
}

// MediaExtensions returns common audio/video file extensions.
func MediaExtensions() []string {
	return []string{".mp4", ".webm", ".mp3", ".wav", ".ogg", ".flac", ".m4a"}
}

// MediaMIMEs returns common audio/video MIME types.
func MediaMIMEs() []string {
	return []string{
		"video/mp4",
		"video/webm",
		"audio/mpeg",
		"audio/wav",
		"audio/ogg",
		"audio/flac",
		"audio/mp4",
	}
}

// ArchiveExtensions returns common compressed archive file extensions.
func ArchiveExtensions() []string {
	return []string{".zip", ".tar", ".gz", ".tgz", ".7z"}
}

// ArchiveMIMEs returns common compressed archive MIME types.
func ArchiveMIMEs() []string {
	return []string{
		"application/zip",
		"application/x-tar",
		"application/gzip",
		"application/x-7z-compressed",
	}
}

// ServeOption aliases for convenient 1-import file serving
type ServeOption = storage.ServeOption

// WithInline instructs the browser to render the file inline.
func WithInline() ServeOption { return storage.WithInline() }

// WithDownload forces the browser to download the file.
func WithDownload() ServeOption { return storage.WithDownload() }

// WithFilename overrides the download filename.
func WithFilename(name string) ServeOption { return storage.WithFilename(name) }

