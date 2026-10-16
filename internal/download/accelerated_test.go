package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestBitset_Operations(t *testing.T) {
	b := NewBitset(64)
	if b.Size() != 64 {
		t.Fatalf("expected size 64, got %d", b.Size())
	}
	if b.CompletedCount() != 0 {
		t.Fatalf("expected 0 completed, got %d", b.CompletedCount())
	}

	b.Set(0)
	b.Set(7)
	b.Set(8)
	b.Set(63)

	if !b.IsSet(0) || !b.IsSet(7) || !b.IsSet(8) || !b.IsSet(63) {
		t.Errorf("expected bits 0, 7, 8, 63 to be set")
	}
	if b.IsSet(1) || b.IsSet(62) {
		t.Errorf("unexpected bit set")
	}
	if b.CompletedCount() != 4 {
		t.Errorf("expected 4 completed, got %d", b.CompletedCount())
	}

	// Test serialization roundtrip
	data := b.Bytes()
	b2 := NewBitsetFromBytes(data, 64)
	if b2.CompletedCount() != 4 {
		t.Errorf("restored bitset completed count mismatch: %d", b2.CompletedCount())
	}
	if !b2.IsSet(63) || !b2.IsSet(0) {
		t.Errorf("restored bitset missing bits")
	}

	b.Clear(7)
	if b.IsSet(7) {
		t.Errorf("bit 7 should be cleared")
	}
	if b.CompletedCount() != 3 {
		t.Errorf("expected 3 completed, got %d", b.CompletedCount())
	}
}

func TestDownloadState_SaveLoad(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "state_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	stateFile := filepath.Join(tmpDir, "task_1.state")
	state := NewDownloadState("task_1", "http://example.com/file.zip", "http://example.com/file.zip", "\"abc123etag\"", "", 10*1024*1024, 2*1024*1024)

	if state.TotalBlocks != 5 {
		t.Fatalf("expected 5 total blocks for 10MB with 2MB blocks, got %d", state.TotalBlocks)
	}

	state.MarkBlockCompleted(0)
	state.MarkBlockCompleted(2)

	if err := state.Save(stateFile); err != nil {
		t.Fatalf("failed saving state: %v", err)
	}

	loaded, err := LoadDownloadState(stateFile)
	if err != nil {
		t.Fatalf("failed loading state: %v", err)
	}

	if loaded.TaskID != "task_1" || loaded.TotalBlocks != 5 {
		t.Errorf("loaded state metadata mismatch: %+v", loaded)
	}
	if !loaded.Bitset().IsSet(0) || !loaded.Bitset().IsSet(2) {
		t.Errorf("loaded bitset missing set bits")
	}
	if loaded.Bitset().IsSet(1) {
		t.Errorf("bit 1 should not be set")
	}
}

func TestPieceCoordinator_AllocationAndHedgedRequeue(t *testing.T) {
	totalSize := int64(6 * 1024 * 1024) // 6MB
	blockSize := int64(2 * 1024 * 1024) // 2MB -> 3 pieces
	stallTimeout := 100 * time.Millisecond

	coord := NewPieceCoordinator(totalSize, blockSize, stallTimeout, 3)
	if coord.totalPieces != 3 {
		t.Fatalf("expected 3 pieces, got %d", coord.totalPieces)
	}

	p0, ok0 := coord.NextPiece(1)
	p1, ok1 := coord.NextPiece(2)
	p2, ok2 := coord.NextPiece(3)
	_, ok3 := coord.NextPiece(4)

	if !ok0 || !ok1 || !ok2 || ok3 {
		t.Fatalf("unexpected piece allocation results: %v, %v, %v, %v", ok0, ok1, ok2, ok3)
	}

	if p0.Index != 0 || p1.Index != 1 || p2.Index != 2 {
		t.Errorf("piece indices out of order: %d, %d, %d", p0.Index, p1.Index, p2.Index)
	}

	// Worker 1 and 2 finish
	coord.MarkCompleted(p0.Index)
	coord.MarkCompleted(p1.Index)

	if coord.IsCompleted() {
		t.Errorf("coord should not be completed yet")
	}

	// Worker 3 stalled (p2)
	time.Sleep(150 * time.Millisecond)

	// Worker 1 is idle and should steal/hedge piece 2
	stolenPiece, stolenOk := coord.NextPiece(1)
	if !stolenOk || stolenPiece.Index != 2 {
		t.Fatalf("expected worker 1 to steal piece 2, got %v, %v", stolenOk, stolenPiece)
	}

	coord.MarkCompleted(stolenPiece.Index)
	if !coord.IsCompleted() {
		t.Errorf("coord should be completed after finishing piece 2")
	}
}

// createMockRangeServer creates an HTTP test server that accurately simulates RFC 7233 byte-range serving.
func createMockRangeServer(content []byte) *httptest.Server {
	hasher := sha256.New()
	hasher.Write(content)
	etag := fmt.Sprintf("\"%s\"", hex.EncodeToString(hasher.Sum(nil)[:8]))

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("ETag", etag)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="large_payload.bin"`)

		totalSize := int64(len(content))

		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.FormatInt(totalSize, 10))
			w.WriteHeader(http.StatusOK)
			return
		}

		rangeHdr := r.Header.Get("Range")
		if rangeHdr == "" {
			w.Header().Set("Content-Length", strconv.FormatInt(totalSize, 10))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(content)
			return
		}

		// Parse Range: bytes=start-end
		if !strings.HasPrefix(rangeHdr, "bytes=") {
			http.Error(w, "invalid range", http.StatusBadRequest)
			return
		}

		parts := strings.Split(strings.TrimPrefix(rangeHdr, "bytes="), "-")
		if len(parts) != 2 {
			http.Error(w, "invalid range spec", http.StatusBadRequest)
			return
		}

		start, err1 := strconv.ParseInt(parts[0], 10, 64)
		var end int64
		if parts[1] == "" {
			end = totalSize - 1
		} else {
			end, _ = strconv.ParseInt(parts[1], 10, 64)
		}

		if err1 != nil || start < 0 || end >= totalSize || start > end {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", totalSize))
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}

		length := end - start + 1
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, totalSize))
		w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(content[start : end+1])
	}))
}

func TestAcceleratedDownloader_ParallelRangeIntegrity(t *testing.T) {
	// Generate 12 MB test payload
	payloadSize := 12 * 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := 0; i < payloadSize; i++ {
		payload[i] = byte((i * 31) % 256)
	}
	expectedHash := sha256.Sum256(payload)

	server := createMockRangeServer(payload)
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "accel_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	targetPath := filepath.Join(tmpDir, "downloaded.bin")
	targetFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer targetFile.Close()

	statePath := filepath.Join(tmpDir, "downloaded.state")

	cfg := &AcceleratedConfig{
		MaxConnections:       6,
		MinBlockSize:         1 * 1024 * 1024,
		MaxBlockSize:         2 * 1024 * 1024,
		MinAccelerationBytes: 2 * 1024 * 1024,
		StallTimeout:         5 * time.Second,
		MaxRetriesPerBlock:   3,
	}

	downloader := NewAcceleratedDownloader(server.Client(), cfg)

	var lastThreads int
	var progressReports int64

	fileInfo, err := downloader.DownloadToFile(
		context.Background(),
		"task_test_integrity",
		server.URL+"/file",
		targetFile,
		statePath,
		func(downloaded, total int64, speed string, threads, completedP, totalP int) {
			atomic.AddInt64(&progressReports, 1)
			lastThreads = threads
		},
		nil,
	)

	if err != nil {
		t.Fatalf("DownloadToFile failed: %v", err)
	}

	if fileInfo.TotalBytes != int64(payloadSize) {
		t.Errorf("expected TotalBytes %d, got %d", payloadSize, fileInfo.TotalBytes)
	}

	// Verify SHA-256 match
	downloadedBytes, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed reading downloaded file: %v", err)
	}
	if len(downloadedBytes) != payloadSize {
		t.Fatalf("expected %d bytes on disk, got %d", payloadSize, len(downloadedBytes))
	}

	actualHash := sha256.Sum256(downloadedBytes)
	if actualHash != expectedHash {
		t.Fatalf("SHA-256 hash mismatch!\nExpected: %x\nActual:   %x", expectedHash, actualHash)
	}

	t.Logf("Successfully downloaded and verified %d bytes using parallel Range acceleration. Reports: %d, Last threads: %d", payloadSize, progressReports, lastThreads)
}

func TestAcceleratedDownloader_Resumption(t *testing.T) {
	// Generate 8 MB test payload
	payloadSize := 8 * 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := 0; i < payloadSize; i++ {
		payload[i] = byte((i * 17) % 256)
	}
	expectedHash := sha256.Sum256(payload)

	server := createMockRangeServer(payload)
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "resume_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	targetPath := filepath.Join(tmpDir, "resumable.bin")
	targetFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}

	statePath := filepath.Join(tmpDir, "resumable.state")

	cfg := &AcceleratedConfig{
		MaxConnections:       4,
		MinBlockSize:         1 * 1024 * 1024,
		MaxBlockSize:         1 * 1024 * 1024, // 8 pieces of 1MB each
		MinAccelerationBytes: 1 * 1024 * 1024,
		StallTimeout:         5 * time.Second,
		MaxRetriesPerBlock:   3,
	}

	downloader := NewAcceleratedDownloader(server.Client(), cfg)

	// Step 1: Pre-populate state as if pieces 0, 1, 2, 3 were already completed
	state := NewDownloadState("task_resume", server.URL+"/file", server.URL+"/file", "", "", int64(payloadSize), 1024*1024)
	_ = targetFile.Truncate(int64(payloadSize))

	for i := 0; i < 4; i++ {
		offset := int64(i * 1024 * 1024)
		_, _ = targetFile.WriteAt(payload[offset:offset+1024*1024], offset)
		state.MarkBlockCompleted(i)
	}
	_ = state.Save(statePath)

	// Step 2: Run DownloadToFile; it should pick up the remaining pieces (4, 5, 6, 7)
	_, err = downloader.DownloadToFile(
		context.Background(),
		"task_resume",
		server.URL+"/file",
		targetFile,
		statePath,
		nil,
		nil,
	)
	_ = targetFile.Close()

	if err != nil {
		t.Fatalf("DownloadToFile with resume failed: %v", err)
	}

	// Verify whole file integrity
	downloadedBytes, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	actualHash := sha256.Sum256(downloadedBytes)
	if actualHash != expectedHash {
		t.Fatalf("Resumed file hash mismatch!\nExpected: %x\nActual:   %x", expectedHash, actualHash)
	}
}

func TestAcceleratedDownloader_FallbackWhenServerDisablesRanges(t *testing.T) {
	// Server that explicitly refuses Range requests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Accept-Ranges", "none")
		w.Header().Set("Content-Type", "application/octet-stream")
		content := []byte("Direct sequential content only")
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(content)
	}))
	defer server.Close()

	tmpDir, _ := os.MkdirTemp("", "fallback_test_*")
	defer os.RemoveAll(tmpDir)

	targetFile, _ := os.Create(filepath.Join(tmpDir, "fallback.bin"))
	defer targetFile.Close()

	cfg := &AcceleratedConfig{
		MaxConnections:       4,
		MinAccelerationBytes: 500, // Small threshold to trigger check
	}
	downloader := NewAcceleratedDownloader(server.Client(), cfg)

	_, err := downloader.DownloadToFile(
		context.Background(),
		"task_fallback",
		server.URL+"/file",
		targetFile,
		"",
		nil,
		nil,
	)

	if err != ErrNotAcceleratable {
		t.Errorf("expected ErrNotAcceleratable for non-range server, got %v", err)
	}
}

func TestAcceleratedDownloader_RateLimitRecovery(t *testing.T) {
	payload := bytes.Repeat([]byte("RateLimitTestData!"), 100*1024) // ~1.8 MB
	var rateLimitCounter int32 = 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Accept-Ranges", "bytes")
		w.Header().Set("Content-Type", "application/octet-stream")

		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", strconv.Itoa(len(payload)))
			w.WriteHeader(http.StatusOK)
			return
		}

		// Inject HTTP 429 on the first 2 range calls
		if atomic.AddInt32(&rateLimitCounter, 1) <= 2 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte("Too Many Requests"))
			return
		}

		rangeHdr := r.Header.Get("Range")
		if strings.HasPrefix(rangeHdr, "bytes=") {
			parts := strings.Split(strings.TrimPrefix(rangeHdr, "bytes="), "-")
			start, _ := strconv.ParseInt(parts[0], 10, 64)
			end, _ := strconv.ParseInt(parts[1], 10, 64)
			length := end - start + 1
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, end, len(payload)))
			w.Header().Set("Content-Length", strconv.FormatInt(length, 10))
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write(payload[start : end+1])
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(payload)
	}))
	defer server.Close()

	tmpDir, _ := os.MkdirTemp("", "ratelimit_test_*")
	defer os.RemoveAll(tmpDir)

	targetFile, _ := os.Create(filepath.Join(tmpDir, "recovered.bin"))
	defer targetFile.Close()

	cfg := &AcceleratedConfig{
		MaxConnections:       2,
		MinBlockSize:         512 * 1024,
		MaxBlockSize:         512 * 1024,
		MinAccelerationBytes: 512 * 1024,
		StallTimeout:         5 * time.Second,
		MaxRetriesPerBlock:   5,
	}

	downloader := NewAcceleratedDownloader(server.Client(), cfg)

	_, err := downloader.DownloadToFile(
		context.Background(),
		"task_ratelimit",
		server.URL+"/file",
		targetFile,
		"",
		nil,
		nil,
	)

	if err != nil {
		t.Fatalf("DownloadToFile failed to recover from rate-limiting: %v", err)
	}

	downloaded, _ := os.ReadFile(targetFile.Name())
	if !bytes.Equal(downloaded, payload) {
		t.Fatalf("Payload corrupted after rate limit recovery")
	}
}

func TestAcceleratedDownloader_TwentyConcurrentConnections(t *testing.T) {
	// Generate 25 MB test payload so 25 pieces of 1MB exist (more pieces than 20 workers)
	payloadSize := 25 * 1024 * 1024
	payload := make([]byte, payloadSize)
	for i := 0; i < payloadSize; i++ {
		payload[i] = byte((i * 47) % 256)
	}
	expectedHash := sha256.Sum256(payload)

	server := createMockRangeServer(payload)
	defer server.Close()

	tmpDir, err := os.MkdirTemp("", "twenty_conn_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	targetPath := filepath.Join(tmpDir, "downloaded_20.bin")
	targetFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer targetFile.Close()

	statePath := filepath.Join(tmpDir, "downloaded_20.state")

	// Use default config which has MaxConnections = 20
	downloader := NewAcceleratedDownloader(server.Client(), nil)
	if downloader.Config.MaxConnections != 20 {
		t.Fatalf("expected DefaultAcceleratedConfig MaxConnections to be 20, got %d", downloader.Config.MaxConnections)
	}

	var maxObservedThreads int32 = 0

	fileInfo, err := downloader.DownloadToFile(
		context.Background(),
		"task_test_twenty_conn",
		server.URL+"/file",
		targetFile,
		statePath,
		func(downloaded, total int64, speed string, threads, completedP, totalP int) {
			for {
				current := atomic.LoadInt32(&maxObservedThreads)
				if int32(threads) <= current || atomic.CompareAndSwapInt32(&maxObservedThreads, current, int32(threads)) {
					break
				}
			}
		},
		nil,
		20, // explicitly requesting 20 threads
	)

	if err != nil {
		t.Fatalf("DownloadToFile with 20 connections failed: %v", err)
	}

	if fileInfo.TotalBytes != int64(payloadSize) {
		t.Errorf("expected TotalBytes %d, got %d", payloadSize, fileInfo.TotalBytes)
	}

	// Verify SHA-256 match
	downloadedBytes, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("failed reading downloaded file: %v", err)
	}
	if len(downloadedBytes) != payloadSize {
		t.Fatalf("expected %d bytes on disk, got %d", payloadSize, len(downloadedBytes))
	}

	actualHash := sha256.Sum256(downloadedBytes)
	if actualHash != expectedHash {
		t.Fatalf("SHA-256 hash mismatch!\nExpected: %x\nActual:   %x", expectedHash, actualHash)
	}

	t.Logf("20-connection test completed successfully! Payload: %d bytes, Max observed active threads: %d", payloadSize, maxObservedThreads)
}
