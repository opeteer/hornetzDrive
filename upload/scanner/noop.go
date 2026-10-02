package scanner

import (
	"context"
	"io"
)

// NoopScanner is a pass-through scanner that considers all files clean.
// Useful for hermetic unit testing and low-security development environments.
type NoopScanner struct{}

// NewNoopScanner returns an active NoopScanner instance.
func NewNoopScanner() *NoopScanner {
	return &NoopScanner{}
}

// Scan always reports clean.
func (s *NoopScanner) Scan(ctx context.Context, r io.ReaderAt, size int64, info FileInfo) (*ScanResult, error) {
	return &ScanResult{
		Clean:       true,
		ScannerName: "Noop",
	}, nil
}
