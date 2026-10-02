package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"ztatic-go-framework/errors"
)

// FileInfo provides metadata about the file being inspected.
type FileInfo struct {
	Filename  string
	Size      int64
	MIME      string
	Extension string
	SHA256    string
}

// ScanResult contains the outcome of a security scan.
type ScanResult struct {
	Clean       bool           `json:"clean"`
	ThreatName  string         `json:"threat_name,omitempty"`
	ScannerName string         `json:"scanner_name"`
	Details     map[string]any `json:"details,omitempty"`
}

// Scanner defines the interface for content security and malware inspection engines.
type Scanner interface {
	Scan(ctx context.Context, r io.ReaderAt, size int64, info FileInfo) (*ScanResult, error)
}

// NewMalwareError returns a standardized Ztatic domain error representing a malware violation.
func NewMalwareError(scannerName, threatName string) *errors.Error {
	return errors.New("MALWARE_DETECTED", fmt.Sprintf("Malware detected by %s: %s", scannerName, threatName)).
		WithStatus(http.StatusForbidden).
		WithMetadata("scanner", scannerName).
		WithMetadata("threat", threatName)
}
