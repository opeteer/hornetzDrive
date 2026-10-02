package filetest

import (
	"context"
	"io"
	"strings"
	"sync"

	"ztatic-go-framework/upload/scanner"
)

// MockScanner is an in-memory, thread-safe test double for scanner.Scanner.
// It allows developers to test malware detection, threat logging, and fail-closed
// scanner resilience without depending on an external daemon (like ClamAV).
type MockScanner struct {
	mu             sync.RWMutex
	scanned        []scanner.FileInfo
	threatAlways   string
	threatPatterns map[string]string
	threatSHA256   map[string]string
	customRule     func(info scanner.FileInfo) (threat string, infected bool)
	failErr        error
	simulateTO     bool
}

// NewMockScanner initializes a MockScanner defaulting to clean results.
func NewMockScanner() *MockScanner {
	return &MockScanner{
		threatPatterns: make(map[string]string),
		threatSHA256:   make(map[string]string),
	}
}

// Scan performs the mock inspection, recording the call spy and evaluating configured rules.
func (m *MockScanner) Scan(ctx context.Context, r io.ReaderAt, size int64, info scanner.FileInfo) (*scanner.ScanResult, error) {
	m.mu.Lock()
	m.scanned = append(m.scanned, info)
	failErr := m.failErr
	simulateTO := m.simulateTO
	threatAlways := m.threatAlways
	m.mu.Unlock()

	if simulateTO {
		return nil, context.DeadlineExceeded
	}
	if failErr != nil {
		return nil, failErr
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// 1. Unconditional threat flag
	if threatAlways != "" {
		return &scanner.ScanResult{
			Clean:       false,
			ThreatName:  threatAlways,
			ScannerName: "MockScanner",
			Details:     map[string]any{"reason": "mock_unconditional_flag"},
		}, nil
	}

	// 2. Filename pattern matches
	for pattern, threat := range m.threatPatterns {
		if strings.Contains(strings.ToLower(info.Filename), strings.ToLower(pattern)) {
			return &scanner.ScanResult{
				Clean:       false,
				ThreatName:  threat,
				ScannerName: "MockScanner",
				Details:     map[string]any{"pattern": pattern},
			}, nil
		}
	}

	// 3. SHA-256 matches
	if threat, ok := m.threatSHA256[strings.ToLower(info.SHA256)]; ok {
		return &scanner.ScanResult{
			Clean:       false,
			ThreatName:  threat,
			ScannerName: "MockScanner",
			Details:     map[string]any{"sha256": info.SHA256},
		}, nil
	}

	// 4. Custom matching function
	if m.customRule != nil {
		if threat, infected := m.customRule(info); infected {
			return &scanner.ScanResult{
				Clean:       false,
				ThreatName:  threat,
				ScannerName: "MockScanner",
				Details:     map[string]any{"rule": "custom"},
			}, nil
		}
	}

	return &scanner.ScanResult{
		Clean:       true,
		ScannerName: "MockScanner",
	}, nil
}

// -----------------------------------------------------------------------------
// Spy & Verification API
// -----------------------------------------------------------------------------

// ScannedFiles returns a copy of all files inspected by this scanner.
func (m *MockScanner) ScannedFiles() []scanner.FileInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	copied := make([]scanner.FileInfo, len(m.scanned))
	copy(copied, m.scanned)
	return copied
}

// ScanCount returns the total number of Scan invocations.
func (m *MockScanner) ScanCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.scanned)
}

// WasScanned returns true if a file with the given filename was inspected.
func (m *MockScanner) WasScanned(filename string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, f := range m.scanned {
		if f.Filename == filename {
			return true
		}
	}
	return false
}

// LastScanned returns the most recently inspected file info, or nil.
func (m *MockScanner) LastScanned() *scanner.FileInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.scanned) == 0 {
		return nil
	}
	f := m.scanned[len(m.scanned)-1]
	return &f
}

// -----------------------------------------------------------------------------
// Behavioral Stubbing API
// -----------------------------------------------------------------------------

// AlwaysClean ensures all scans return clean without errors.
func (m *MockScanner) AlwaysClean() *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threatAlways = ""
	m.failErr = nil
	m.simulateTO = false
	return m
}

// FlagThreat causes all subsequent scans to report infected with the specified threat name.
func (m *MockScanner) FlagThreat(threatName string) *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threatAlways = threatName
	return m
}

// FlagFilename flags any file whose filename contains pattern (case-insensitive) as infected.
func (m *MockScanner) FlagFilename(pattern, threatName string) *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threatPatterns[pattern] = threatName
	return m
}

// FlagSHA256 flags any file with matching SHA-256 hash as infected.
func (m *MockScanner) FlagSHA256(sha256Hex, threatName string) *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.threatSHA256[strings.ToLower(sha256Hex)] = threatName
	return m
}

// FlagThreatWhen registers a custom inspection predicate.
func (m *MockScanner) FlagThreatWhen(fn func(info scanner.FileInfo) (string, bool)) *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.customRule = fn
	return m
}

// FailWithError causes Scan to return an explicit error (useful for testing FailClosedScanner).
func (m *MockScanner) FailWithError(err error) *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failErr = err
	return m
}

// SimulateTimeout causes Scan to return context.DeadlineExceeded.
func (m *MockScanner) SimulateTimeout() *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.simulateTO = true
	return m
}

// Reset clears all recorded calls, error stubs, and threat rules.
func (m *MockScanner) Reset() *MockScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scanned = nil
	m.threatAlways = ""
	m.threatPatterns = make(map[string]string)
	m.threatSHA256 = make(map[string]string)
	m.customRule = nil
	m.failErr = nil
	m.simulateTO = false
	return m
}
