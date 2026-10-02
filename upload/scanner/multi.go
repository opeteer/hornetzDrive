package scanner

import (
	"context"
	"fmt"
	"io"
)

// MultiScanner runs multiple scanners sequentially in a pipeline.
// If any scanner flags the file as infected, the pipeline stops and reports the threat.
type MultiScanner struct {
	scanners []Scanner
}

// NewMultiScanner creates a composite scanner wrapping the provided scanners.
func NewMultiScanner(scanners ...Scanner) *MultiScanner {
	active := make([]Scanner, 0, len(scanners))
	for _, s := range scanners {
		if s != nil {
			active = append(active, s)
		}
	}
	return &MultiScanner{scanners: active}
}

// Scan executes each registered scanner in order.
func (m *MultiScanner) Scan(ctx context.Context, r io.ReaderAt, size int64, info FileInfo) (*ScanResult, error) {
	for _, sc := range m.scanners {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		res, err := sc.Scan(ctx, r, size, info)
		if err != nil {
			return nil, fmt.Errorf("scanner %T failed: %w", sc, err)
		}
		if res != nil && !res.Clean {
			return res, nil // Stop at first detected threat
		}
	}

	return &ScanResult{
		Clean:       true,
		ScannerName: "MultiScanner",
	}, nil
}
