package upload

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gabriel-vasile/mimetype"
	"ztatic-go-framework/errors"
)

// ValidationResult contains the verified metadata of an inspected file.
type ValidationResult struct {
	MIME      string `json:"mime"`
	Extension string `json:"extension"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Width     int    `json:"width,omitempty"`
	Height    int    `json:"height,omitempty"`
}

// Validator validates file size, magic-byte MIME types, extensions, and image dimensions.
type Validator struct {
	cfg Config
}

// NewValidator initializes a file validator with default settings.
func NewValidator() *Validator {
	return NewValidatorWithConfig(DefaultConfig())
}

// NewValidatorWithConfig initializes a file validator with the specified Config.
func NewValidatorWithConfig(cfg Config) *Validator {
	return &Validator{cfg: cfg}
}

// MaxBytes sets the maximum allowed file size.
func (v *Validator) MaxBytes(max int64) *Validator {
	v.cfg.MaxFileSize = max
	return v
}

// MinBytes sets the minimum allowed file size.
func (v *Validator) MinBytes(min int64) *Validator {
	v.cfg.MinFileSize = min
	return v
}

// AllowedMIMEs sets the allowlist of permitted MIME types.
func (v *Validator) AllowedMIMEs(mimes ...string) *Validator {
	v.cfg.AllowedMIMEs = mimes
	return v
}

// AllowedExtensions sets the allowlist of permitted file extensions.
func (v *Validator) AllowedExtensions(exts ...string) *Validator {
	normalized := make([]string, len(exts))
	for i, ext := range exts {
		ext = strings.ToLower(strings.TrimSpace(ext))
		if ext != "" && !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		normalized[i] = ext
	}
	v.cfg.AllowedExtensions = normalized
	return v
}

// MaxDimensions sets the maximum width and height bounds for images.
func (v *Validator) MaxDimensions(width, height int) *Validator {
	if v.cfg.ImageDimensions == nil {
		v.cfg.ImageDimensions = &Dimensions{}
	}
	v.cfg.ImageDimensions.MaxWidth = width
	v.cfg.ImageDimensions.MaxHeight = height
	return v
}

// MinDimensions sets the minimum width and height bounds for images.
func (v *Validator) MinDimensions(width, height int) *Validator {
	if v.cfg.ImageDimensions == nil {
		v.cfg.ImageDimensions = &Dimensions{}
	}
	v.cfg.ImageDimensions.MinWidth = width
	v.cfg.ImageDimensions.MinHeight = height
	return v
}

// ValidateFileHeader validates a multipart.FileHeader received from an HTTP upload.
func (v *Validator) ValidateFileHeader(ctx context.Context, fh *multipart.FileHeader) (*ValidationResult, error) {
	if fh == nil {
		return nil, errors.BadRequest("Missing uploaded file")
	}

	// 1. Initial size check from multipart header
	if v.cfg.MaxFileSize > 0 && fh.Size > v.cfg.MaxFileSize {
		return nil, errors.New("FILE_TOO_LARGE", fmt.Sprintf("File size (%d bytes) exceeds maximum limit of %d bytes", fh.Size, v.cfg.MaxFileSize)).
			WithStatus(http.StatusRequestEntityTooLarge)
	}

	file, err := fh.Open()
	if err != nil {
		return nil, errors.BadRequest("Failed to open uploaded file").WithInternal(err)
	}
	defer file.Close()

	ra, ok := file.(io.ReaderAt)
	if !ok {
		// In case file is purely streaming, buffer to ReadSeeker/ReaderAt
		buf, err := io.ReadAll(file)
		if err != nil {
			return nil, errors.Internal("Failed to read file buffer").WithInternal(err)
		}
		return v.ValidateReader(ctx, strings.NewReader(string(buf)), int64(len(buf)), fh.Filename)
	}

	return v.ValidateReader(ctx, ra, fh.Size, fh.Filename)
}

// ValidateReader performs deep magic-byte, extension, and dimension inspection on an io.ReaderAt.
func (v *Validator) ValidateReader(ctx context.Context, r io.ReaderAt, size int64, filename string) (*ValidationResult, error) {
	// 1. Enforce size bounds
	if v.cfg.MaxFileSize > 0 && size > v.cfg.MaxFileSize {
		return nil, errors.New("FILE_TOO_LARGE", fmt.Sprintf("File size (%d bytes) exceeds maximum limit of %d bytes", size, v.cfg.MaxFileSize)).
			WithStatus(http.StatusRequestEntityTooLarge)
	}
	if v.cfg.MinFileSize > 0 && size < v.cfg.MinFileSize {
		return nil, errors.New("FILE_TOO_SMALL", fmt.Sprintf("File size (%d bytes) is smaller than minimum required limit of %d bytes", size, v.cfg.MinFileSize)).
			WithStatus(http.StatusBadRequest)
	}

	// 2. Read magic bytes header for MIME sniffing
	sniffSize := int64(4096)
	if size < sniffSize {
		sniffSize = size
	}
	sniffBuf := make([]byte, sniffSize)
	if _, err := r.ReadAt(sniffBuf, 0); err != nil && err != io.EOF {
		return nil, errors.Internal("Failed to read file signature").WithInternal(err)
	}

	mtype := mimetype.Detect(sniffBuf)
	detectedMIME := mtype.String()

	// 3. Verify MIME Allowlist
	if len(v.cfg.AllowedMIMEs) > 0 {
		matched := false
		for _, allowed := range v.cfg.AllowedMIMEs {
			if strings.EqualFold(detectedMIME, allowed) || mtype.Is(allowed) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, errors.New("UNSUPPORTED_MEDIA_TYPE", fmt.Sprintf("Unsupported file MIME type: %s", detectedMIME)).
				WithStatus(http.StatusUnsupportedMediaType).
				WithMetadata("detected_mime", detectedMIME)
		}
	}

	// 4. Verify Extension Allowlist
	ext := strings.ToLower(filepath.Ext(SanitizeFilename(filename)))
	if len(v.cfg.AllowedExtensions) > 0 {
		matched := false
		for _, allowed := range v.cfg.AllowedExtensions {
			if strings.EqualFold(ext, allowed) {
				matched = true
				break
			}
		}
		if !matched {
			return nil, errors.New("UNSUPPORTED_EXTENSION", fmt.Sprintf("Unsupported file extension: %s", ext)).
				WithStatus(http.StatusBadRequest).
				WithMetadata("extension", ext)
		}
	}

	// 5. Anti-Spoofing: Verify extension matches sniffed MIME category
	if err := checkMIMEExtensionConsistency(ext, detectedMIME); err != nil {
		return nil, err
	}

	// 6. Deep Image Dimension Inspection (zero-raster pixel decoding)
	var width, height int
	if strings.HasPrefix(detectedMIME, "image/") && detectedMIME != "image/svg+xml" {
		secReader := io.NewSectionReader(r, 0, size)
		cfg, _, err := image.DecodeConfig(secReader)
		if err == nil {
			width = cfg.Width
			height = cfg.Height

			if v.cfg.ImageDimensions != nil {
				d := v.cfg.ImageDimensions
				if d.MaxWidth > 0 && width > d.MaxWidth {
					return nil, errors.BadRequest(fmt.Sprintf("Image width (%dpx) exceeds maximum allowed (%dpx)", width, d.MaxWidth))
				}
				if d.MaxHeight > 0 && height > d.MaxHeight {
					return nil, errors.BadRequest(fmt.Sprintf("Image height (%dpx) exceeds maximum allowed (%dpx)", height, d.MaxHeight))
				}
				if d.MinWidth > 0 && width < d.MinWidth {
					return nil, errors.BadRequest(fmt.Sprintf("Image width (%dpx) is below minimum required (%dpx)", width, d.MinWidth))
				}
				if d.MinHeight > 0 && height < d.MinHeight {
					return nil, errors.BadRequest(fmt.Sprintf("Image height (%dpx) is below minimum required (%dpx)", height, d.MinHeight))
				}
			}
		}
	}

	// 7. Compute SHA-256 Hash
	h := sha256.New()
	secReader := io.NewSectionReader(r, 0, size)
	if _, err := io.Copy(h, secReader); err != nil {
		return nil, errors.Internal("Failed to compute file hash").WithInternal(err)
	}
	hashStr := hex.EncodeToString(h.Sum(nil))

	return &ValidationResult{
		MIME:      detectedMIME,
		Extension: ext,
		Size:      size,
		SHA256:    hashStr,
		Width:     width,
		Height:    height,
	}, nil
}

// checkMIMEExtensionConsistency detects polyglot/spoofing attacks where a dangerous file
// masquerades under a harmless extension (e.g. executable disguised as .png).
func checkMIMEExtensionConsistency(ext, detectedMIME string) error {
	if ext == "" || detectedMIME == "" {
		return nil
	}

	// If extension claims to be an image but MIME is executable or script
	imageExts := map[string]bool{".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".webp": true}
	if imageExts[ext] {
		if strings.HasPrefix(detectedMIME, "application/x-") ||
			detectedMIME == "text/html" ||
			detectedMIME == "text/javascript" ||
			detectedMIME == "application/javascript" {
			return errors.New("MIME_EXTENSION_MISMATCH", fmt.Sprintf("File with extension %s has incompatible MIME type %s", ext, detectedMIME)).
				WithStatus(http.StatusBadRequest)
		}
	}

	return nil
}
