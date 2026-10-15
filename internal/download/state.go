package download

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Bitset represents a compact concurrent-safe bit vector for tracking completed blocks.
type Bitset struct {
	mu   sync.RWMutex
	data []byte
	size int
}

// NewBitset initializes a bitset for the given number of bits.
func NewBitset(size int) *Bitset {
	numBytes := (size + 7) / 8
	return &Bitset{
		data: make([]byte, numBytes),
		size: size,
	}
}

// NewBitsetFromBytes restores a bitset from existing byte slice.
func NewBitsetFromBytes(data []byte, size int) *Bitset {
	numBytes := (size + 7) / 8
	b := make([]byte, numBytes)
	copy(b, data)
	return &Bitset{
		data: b,
		size: size,
	}
}

// Set marks a block index as completed (1).
func (b *Bitset) Set(index int) {
	if index < 0 || index >= b.size {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[index/8] |= (1 << (uint(index) % 8))
}

// Clear marks a block index as incomplete (0).
func (b *Bitset) Clear(index int) {
	if index < 0 || index >= b.size {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.data[index/8] &= ^(1 << (uint(index) % 8))
}

// IsSet returns whether the block index is marked completed.
func (b *Bitset) IsSet(index int) bool {
	if index < 0 || index >= b.size {
		return false
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	return (b.data[index/8] & (1 << (uint(index) % 8))) != 0
}

// CompletedCount returns the total number of set bits.
func (b *Bitset) CompletedCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	count := 0
	for i := 0; i < b.size; i++ {
		if (b.data[i/8] & (1 << (uint(i) % 8))) != 0 {
			count++
		}
	}
	return count
}

// Bytes returns a copy of the underlying bytes.
func (b *Bitset) Bytes() []byte {
	b.mu.RLock()
	defer b.mu.RUnlock()
	dup := make([]byte, len(b.data))
	copy(dup, b.data)
	return dup
}

// Size returns the total capacity in bits.
func (b *Bitset) Size() int {
	return b.size
}

// IsAllSet returns true if all blocks are marked completed.
func (b *Bitset) IsAllSet() bool {
	return b.CompletedCount() == b.size
}

// DownloadState records the progress journal for a multi-threaded accelerated download.
type DownloadState struct {
	TaskID       string    `json:"task_id"`
	URL          string    `json:"url"`
	ResolvedURL  string    `json:"resolved_url"`
	ETag         string    `json:"etag"`
	LastModified string    `json:"last_modified"`
	TotalBytes   int64     `json:"total_bytes"`
	BlockSize    int64     `json:"block_size"`
	TotalBlocks  int       `json:"total_blocks"`
	BitsetBytes  []byte    `json:"bitset_bytes"`
	UpdatedAt    time.Time `json:"updated_at"`

	mu     sync.RWMutex `json:"-"`
	bitset *Bitset      `json:"-"`
}

// NewDownloadState creates an initialized state instance.
func NewDownloadState(taskID, url, resolvedURL, etag, lastModified string, totalBytes, blockSize int64) *DownloadState {
	if blockSize <= 0 {
		blockSize = 2 * 1024 * 1024
	}
	totalBlocks := int((totalBytes + blockSize - 1) / blockSize)
	if totalBlocks <= 0 {
		totalBlocks = 1
	}

	bitset := NewBitset(totalBlocks)
	return &DownloadState{
		TaskID:       taskID,
		URL:          url,
		ResolvedURL:  resolvedURL,
		ETag:         etag,
		LastModified: lastModified,
		TotalBytes:   totalBytes,
		BlockSize:    blockSize,
		TotalBlocks:  totalBlocks,
		BitsetBytes:  bitset.Bytes(),
		UpdatedAt:    time.Now(),
		bitset:       bitset,
	}
}

// Bitset returns the thread-safe bitset tracker.
func (s *DownloadState) Bitset() *Bitset {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.bitset
}

// MarkBlockCompleted marks a block complete and refreshes BitsetBytes.
func (s *DownloadState) MarkBlockCompleted(blockIndex int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.bitset == nil {
		s.bitset = NewBitsetFromBytes(s.BitsetBytes, s.TotalBlocks)
	}
	s.bitset.Set(blockIndex)
	s.BitsetBytes = s.bitset.Bytes()
	s.UpdatedAt = time.Now()
}

// Save persists the state to disk atomically using a temporary file.
func (s *DownloadState) Save(filePath string) error {
	s.mu.Lock()
	if s.bitset != nil {
		s.BitsetBytes = s.bitset.Bytes()
	}
	s.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(s, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}

	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	tmpFile := filePath + ".tmp"
	if err := os.WriteFile(tmpFile, data, 0600); err != nil {
		return err
	}

	return os.Rename(tmpFile, filePath)
}

// LoadDownloadState reads a saved state journal from disk.
func LoadDownloadState(filePath string) (*DownloadState, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var state DownloadState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("corrupt download state file: %w", err)
	}

	state.bitset = NewBitsetFromBytes(state.BitsetBytes, state.TotalBlocks)
	return &state, nil
}

// ValidateRemoteIntegrity checks whether the remote file has changed using ETag or Last-Modified.
func (s *DownloadState) ValidateRemoteIntegrity(ctx context.Context, client *http.Client) (bool, error) {
	if client == nil {
		client = http.DefaultClient
	}

	reqURL := s.ResolvedURL
	if reqURL == "" {
		reqURL = s.URL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, reqURL, nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("User-Agent", DefaultBrowserUserAgent)

	if s.ETag != "" {
		req.Header.Set("If-Match", s.ETag)
	} else if s.LastModified != "" {
		req.Header.Set("If-Unmodified-Since", s.LastModified)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusPreconditionFailed {
		return false, nil
	}

	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusPartialContent {
		// Verify size matches
		if s.TotalBytes > 0 && resp.ContentLength > 0 && resp.ContentLength != s.TotalBytes {
			return false, nil
		}
		// If ETag exists, compare
		if s.ETag != "" {
			respETag := resp.Header.Get("ETag")
			if respETag != "" && respETag != s.ETag {
				return false, nil
			}
		}
		return true, nil
	}

	return false, errors.New("unexpected preflight status code: " + resp.Status)
}
