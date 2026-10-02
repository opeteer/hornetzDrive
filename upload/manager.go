package upload

import (
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/errors"
	"ztatic-go-framework/security/audit"
	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
)

// ProcessedFile encapsulates a validated, scanned, and persisted file.
type ProcessedFile struct {
	Key          string            `json:"key"`
	OriginalName string            `json:"original_name"`
	Size         int64             `json:"size"`
	MIME         string            `json:"mime"`
	Extension    string            `json:"extension"`
	SHA256       string            `json:"sha256"`
	Width        int               `json:"width,omitempty"`
	Height       int               `json:"height,omitempty"`
	URL          string            `json:"url,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
	CreatedAt    time.Time         `json:"created_at"`
}

// Manager orchestrates the complete upload pipeline: ingestion, validation, malware scanning, and storage.
type Manager struct {
	cfg       Config
	validator *Validator
	scanner   scanner.Scanner
	storage   storage.Storage
}

// NewManager initializes an upload Manager with the provided Config.
func NewManager(cfg Config) (*Manager, error) {
	if cfg.Storage == nil {
		// Default to in-memory storage if none provided
		cfg.Storage = storage.NewMemoryStorage()
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = 10 * MB
	}
	if cfg.MaxMemory <= 0 {
		cfg.MaxMemory = 32 * MB
	}
	if cfg.UploadTimeout <= 0 {
		cfg.UploadTimeout = 60 * time.Second
	}

	return &Manager{
		cfg:       cfg,
		validator: NewValidatorWithConfig(cfg),
		scanner:   cfg.Scanner,
		storage:   cfg.Storage,
	}, nil
}

// Validator returns the manager's validator.
func (m *Manager) Validator() *Validator {
	return m.validator
}

// Storage returns the manager's storage driver.
func (m *Manager) Storage() storage.Storage {
	return m.storage
}

// Scanner returns the manager's scanner engine.
func (m *Manager) Scanner() scanner.Scanner {
	return m.scanner
}

// Process parses and processes a single file upload from the Echo context.
func (m *Manager) Process(c *echo.Context, fieldName string) (*ProcessedFile, error) {
	fh, err := c.FormFile(fieldName)
	if err != nil {
		return nil, errors.BadRequest(fmt.Sprintf("Failed to retrieve file from form field %q: %v", fieldName, err))
	}

	res, err := m.ProcessFileHeader(c.Request().Context(), fh)
	if err != nil {
		var appErr *errors.Error
		if errors.As(err, &appErr) && appErr.Code == "MALWARE_DETECTED" {
			audit.Record(c, "file.malware_blocked", "file", fh.Filename)
		}
		return nil, err
	}
	return res, nil
}

// ProcessMultiple parses and processes all uploaded files matching the specified form field name.
func (m *Manager) ProcessMultiple(c *echo.Context, fieldName string) ([]*ProcessedFile, error) {
	mf, err := c.MultipartForm()
	if err != nil {
		return nil, errors.BadRequest(fmt.Sprintf("Failed to parse multipart form: %v", err))
	}

	files := mf.File[fieldName]
	if len(files) == 0 {
		return nil, errors.BadRequest(fmt.Sprintf("No files found under field %q", fieldName))
	}

	ctx := c.Request().Context()
	results := make([]*ProcessedFile, 0, len(files))
	for _, fh := range files {
		res, err := m.ProcessFileHeader(ctx, fh)
		if err != nil {
			var appErr *errors.Error
			if errors.As(err, &appErr) && appErr.Code == "MALWARE_DETECTED" {
				audit.Record(c, "file.malware_blocked", "file", fh.Filename)
			}
			return nil, err
		}
		results = append(results, res)
	}

	return results, nil
}

// ProcessFileHeader executes validation, scanning, key generation, and storage for a multipart.FileHeader.
func (m *Manager) ProcessFileHeader(ctx context.Context, fh *multipart.FileHeader) (*ProcessedFile, error) {
	if fh == nil {
		return nil, errors.BadRequest("Missing uploaded file")
	}

	if m.cfg.UploadTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, m.cfg.UploadTimeout)
		defer cancel()
	}

	file, err := fh.Open()
	if err != nil {
		return nil, errors.BadRequest("Failed to open file header").WithInternal(err)
	}
	defer file.Close()

	ra, ok := file.(io.ReaderAt)
	if !ok {
		// Read into memory if not ReaderAt
		buf, err := io.ReadAll(file)
		if err != nil {
			return nil, errors.Internal("Failed to read file content").WithInternal(err)
		}
		return m.ProcessReader(ctx, strings.NewReader(string(buf)), int64(len(buf)), fh.Filename)
	}

	return m.ProcessReader(ctx, ra, fh.Size, fh.Filename)
}

// ProcessReader executes validation, scanning, and storage on an io.ReaderAt.
func (m *Manager) ProcessReader(ctx context.Context, r io.ReaderAt, size int64, originalFilename string) (*ProcessedFile, error) {
	// 1. Validation (MIME sniffing, extensions, sizes, image dimensions)
	valRes, err := m.validator.ValidateReader(ctx, r, size, originalFilename)
	if err != nil {
		return nil, err
	}

	// 2. Malware & Content Security Scanning
	if m.scanner != nil {
		scanInfo := scanner.FileInfo{
			Filename:  originalFilename,
			Size:      size,
			MIME:      valRes.MIME,
			Extension: valRes.Extension,
			SHA256:    valRes.SHA256,
		}

		scanRes, err := m.scanner.Scan(ctx, r, size, scanInfo)
		if err != nil {
			if m.cfg.FailClosedScanner {
				return nil, errors.Internal("Security scanner failed").WithInternal(err)
			}
		} else if scanRes != nil && !scanRes.Clean {
			return nil, scanner.NewMalwareError(scanRes.ScannerName, scanRes.ThreatName)
		}
	}

	// 3. Generate Storage Key
	var sampleContent []byte
	if m.cfg.NamingStrategy == StrategySHA256 && size <= 2*MB {
		sampleContent = make([]byte, size)
		_, _ = r.ReadAt(sampleContent, 0)
	}
	key := GenerateStorageKey(m.cfg.NamingStrategy, originalFilename, sampleContent, m.cfg.CustomNamingFunc)

	// 4. Persist to Storage Engine
	secReader := io.NewSectionReader(r, 0, size)
	saveOpts := storage.SaveOptions{
		OriginalName: SanitizeFilename(originalFilename),
		MIME:         valRes.MIME,
		Extension:    valRes.Extension,
		SHA256:       valRes.SHA256,
	}

	record, err := m.storage.Save(ctx, key, secReader, size, saveOpts)
	if err != nil {
		return nil, errors.Internal("Failed to save file to storage").WithInternal(err)
	}

	// 5. Generate URL
	url, _ := m.storage.URL(ctx, key, storage.URLOptions{Filename: record.OriginalName})

	return &ProcessedFile{
		Key:          record.Key,
		OriginalName: record.OriginalName,
		Size:         record.Size,
		MIME:         record.MIME,
		Extension:    record.Extension,
		SHA256:       record.SHA256,
		Width:        valRes.Width,
		Height:       valRes.Height,
		URL:          url,
		CreatedAt:    record.CreatedAt,
	}, nil
}
