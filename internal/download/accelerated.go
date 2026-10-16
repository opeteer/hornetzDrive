package download

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// AcceleratedConfig controls the concurrency and block allocation for multi-threaded downloads.
type AcceleratedConfig struct {
	MaxConnections       int           // Max parallel worker connections (default 20)
	MinBlockSize         int64         // Minimum chunk size (default 1MB)
	MaxBlockSize         int64         // Maximum chunk size (default 8MB)
	MinAccelerationBytes int64         // Threshold below which single-threaded is used (default 5MB)
	StallTimeout         time.Duration // Duration of inactivity before a block is re-queued (default 12s)
	MaxRetriesPerBlock   int           // Max retries for a failing block (default 4)
}

func DefaultAcceleratedConfig() AcceleratedConfig {
	return AcceleratedConfig{
		MaxConnections:       20,
		MinBlockSize:         1 * 1024 * 1024,
		MaxBlockSize:         8 * 1024 * 1024,
		MinAccelerationBytes: 5 * 1024 * 1024,
		StallTimeout:         12 * time.Second,
		MaxRetriesPerBlock:   4,
	}
}

type PieceStatus int

const (
	PiecePending PieceStatus = iota
	PieceInFlight
	PieceCompleted
	PieceFailed
)

// Piece describes a specific byte-range slice of the file.
type Piece struct {
	Index       int
	StartOffset int64
	EndOffset   int64 // Inclusive: bytes=StartOffset-EndOffset
	Length      int64
	Status      PieceStatus
	WorkerID    int
	Attempts    int
	LastActive  time.Time
}

// PieceCoordinator manages thread-safe distribution and state tracking of pieces.
type PieceCoordinator struct {
	mu           sync.Mutex
	pieces       []*Piece
	completed    int64
	totalBytes   int64
	totalPieces  int
	stallTimeout time.Duration
	maxRetries   int
}

func NewPieceCoordinator(totalBytes, blockSize int64, stallTimeout time.Duration, maxRetries int) *PieceCoordinator {
	if blockSize <= 0 {
		blockSize = 2 * 1024 * 1024
	}
	totalPieces := int((totalBytes + blockSize - 1) / blockSize)
	if totalPieces <= 0 {
		totalPieces = 1
	}

	pieces := make([]*Piece, totalPieces)
	for i := 0; i < totalPieces; i++ {
		start := int64(i) * blockSize
		end := start + blockSize - 1
		if end >= totalBytes {
			end = totalBytes - 1
		}
		pieces[i] = &Piece{
			Index:       i,
			StartOffset: start,
			EndOffset:   end,
			Length:      end - start + 1,
			Status:      PiecePending,
		}
	}

	return &PieceCoordinator{
		pieces:       pieces,
		totalBytes:   totalBytes,
		totalPieces:  totalPieces,
		stallTimeout: stallTimeout,
		maxRetries:   maxRetries,
	}
}

// ApplyBitset restores completed pieces from an existing saved bitset.
func (pc *PieceCoordinator) ApplyBitset(b *Bitset) int64 {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	var restoredBytes int64 = 0
	for i := 0; i < pc.totalPieces && i < b.Size(); i++ {
		if b.IsSet(i) {
			pc.pieces[i].Status = PieceCompleted
			restoredBytes += pc.pieces[i].Length
			atomic.AddInt64(&pc.completed, 1)
		}
	}
	return restoredBytes
}

// NextPiece returns the next pending or stalled piece to download.
func (pc *PieceCoordinator) NextPiece(workerID int) (*Piece, bool) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	now := time.Now()

	// 1. First priority: completely unassigned pending pieces
	for _, p := range pc.pieces {
		if p.Status == PiecePending {
			p.Status = PieceInFlight
			p.WorkerID = workerID
			p.LastActive = now
			p.Attempts++
			return p, true
		}
	}

	// 2. Second priority: hedged execution for stalled in-flight pieces
	for _, p := range pc.pieces {
		if p.Status == PieceInFlight && p.WorkerID != workerID && now.Sub(p.LastActive) > pc.stallTimeout {
			if p.Attempts < pc.maxRetries {
				p.WorkerID = workerID
				p.LastActive = now
				p.Attempts++
				return p, true
			}
		}
	}

	return nil, false
}

// MarkCompleted transitions a piece to PieceCompleted.
func (pc *PieceCoordinator) MarkCompleted(index int) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if index >= 0 && index < len(pc.pieces) {
		if pc.pieces[index].Status != PieceCompleted {
			pc.pieces[index].Status = PieceCompleted
			atomic.AddInt64(&pc.completed, 1)
		}
	}
}

// RequeuePiece resets an in-flight piece back to PiecePending.
func (pc *PieceCoordinator) RequeuePiece(index int) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if index >= 0 && index < len(pc.pieces) {
		if pc.pieces[index].Status != PieceCompleted {
			if pc.pieces[index].Attempts >= pc.maxRetries {
				pc.pieces[index].Status = PieceFailed
			} else {
				pc.pieces[index].Status = PiecePending
			}
		}
	}
}

// TouchPiece updates the activity timestamp of a piece.
func (pc *PieceCoordinator) TouchPiece(index int) {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if index >= 0 && index < len(pc.pieces) {
		pc.pieces[index].LastActive = time.Now()
	}
}

// IsCompleted returns true if all pieces have been downloaded.
func (pc *PieceCoordinator) IsCompleted() bool {
	return atomic.LoadInt64(&pc.completed) >= int64(pc.totalPieces)
}

// Progress returns completed pieces and total pieces.
func (pc *PieceCoordinator) Progress() (int, int) {
	return int(atomic.LoadInt64(&pc.completed)), pc.totalPieces
}

// AcceleratedDownloader handles multi-connection dynamic segmentation downloads.
type AcceleratedDownloader struct {
	HTTPClient *http.Client
	Config     AcceleratedConfig
}

func NewAcceleratedDownloader(client *http.Client, config *AcceleratedConfig) *AcceleratedDownloader {
	cfg := DefaultAcceleratedConfig()
	if config != nil {
		if config.MaxConnections > 0 {
			cfg.MaxConnections = config.MaxConnections
		}
		if config.MinBlockSize > 0 {
			cfg.MinBlockSize = config.MinBlockSize
		}
		if config.MaxBlockSize > 0 {
			cfg.MaxBlockSize = config.MaxBlockSize
		}
		if config.MinAccelerationBytes > 0 {
			cfg.MinAccelerationBytes = config.MinAccelerationBytes
		}
		if config.StallTimeout > 0 {
			cfg.StallTimeout = config.StallTimeout
		}
		if config.MaxRetriesPerBlock > 0 {
			cfg.MaxRetriesPerBlock = config.MaxRetriesPerBlock
		}
	}

	if client == nil {
		client = NewSafeHTTPClient(2*time.Hour, 15, false)
	}

	return &AcceleratedDownloader{
		HTTPClient: client,
		Config:     cfg,
	}
}

// ComputeDynamicBlockSize calculates optimal chunk size based on file size.
func ComputeDynamicBlockSize(totalBytes int64, minBlock, maxBlock int64) int64 {
	if totalBytes <= 0 {
		return minBlock
	}
	// Target ~32-128 blocks for balanced concurrency without excessive HTTP handshakes
	targetBlocks := int64(64)
	calculated := totalBytes / targetBlocks
	if calculated < minBlock {
		return minBlock
	}
	if calculated > maxBlock {
		return maxBlock
	}
	return calculated
}

// DownloadToFile executes the multi-threaded range download writing to targetFile.
func (ad *AcceleratedDownloader) DownloadToFile(
	ctx context.Context,
	taskID string,
	targetURL string,
	targetFile *os.File,
	statePath string,
	onProgress func(downloaded int64, total int64, speed string, threads int, completedBlocks int, totalBlocks int),
	onMeta func(meta *DirectFileInfo),
	maxThreads ...int,
) (*DirectFileInfo, error) {

	// 1. Resolve Link & Preflight Probe
	resolved, err := ResolveLink(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed resolving target link: %w", err)
	}

	execURL := resolved.ResolvedURL
	if _, err := ValidateSafeURL(execURL, false); err != nil {
		return nil, err
	}

	probeRes, err := ProbeLink(ctx, ad.HTTPClient, execURL)
	if err != nil {
		return nil, fmt.Errorf("preflight probe failed: %w", err)
	}

	totalBytes := probeRes.FileSize
	resumable := probeRes.Resumable
	filename := probeRes.Filename
	mimeType := probeRes.MimeType

	// If not eligible for acceleration, return sentinel error so caller can fallback
	if !resumable || totalBytes < ad.Config.MinAccelerationBytes {
		return nil, ErrNotAcceleratable
	}

	// 2. Pre-allocate sparse target file
	if err := targetFile.Truncate(totalBytes); err != nil {
		return nil, fmt.Errorf("failed to pre-allocate sparse file (%d bytes): %w", totalBytes, err)
	}

	// 3. Initialize or restore DownloadState and PieceCoordinator
	blockSize := ComputeDynamicBlockSize(totalBytes, ad.Config.MinBlockSize, ad.Config.MaxBlockSize)
	var state *DownloadState
	var downloadedBytes int64 = 0

	if statePath != "" {
		if existingState, err := LoadDownloadState(statePath); err == nil && existingState.TotalBytes == totalBytes {
			// Verify remote immutability
			valid, _ := existingState.ValidateRemoteIntegrity(ctx, ad.HTTPClient)
			if valid {
				state = existingState
			}
		}
	}

	if state == nil {
		state = NewDownloadState(taskID, targetURL, execURL, probeRes.FinalURL, "", totalBytes, blockSize)
	}

	coord := NewPieceCoordinator(totalBytes, blockSize, ad.Config.StallTimeout, ad.Config.MaxRetriesPerBlock)
	if state.Bitset().CompletedCount() > 0 {
		downloadedBytes = coord.ApplyBitset(state.Bitset())
	}

	fileInfo := &DirectFileInfo{
		Filename:   filename,
		MimeType:   mimeType,
		TotalBytes: totalBytes,
	}
	if onMeta != nil {
		onMeta(fileInfo)
	}

	// 4. Setup Worker Pool
	concurrency := ad.Config.MaxConnections
	if len(maxThreads) > 0 && maxThreads[0] > 0 {
		concurrency = maxThreads[0]
	}
	if concurrency <= 0 {
		concurrency = 20
	}
	if concurrency > 32 {
		concurrency = 32
	}
	// Don't spawn more workers than total pieces
	if coord.totalPieces < concurrency {
		concurrency = coord.totalPieces
	}

	var activeThreads int32 = 0
	var bytesCounter int64 = downloadedBytes
	lastSpeedBytes := bytesCounter
	lastSpeedTime := time.Now()

	errChan := make(chan error, concurrency)
	workerCtx, cancelWorkers := context.WithCancel(ctx)
	defer cancelWorkers()

	var wg sync.WaitGroup

	// Periodic state saver & progress reporter goroutine
	progressStop := make(chan struct{})
	go func() {
		ticker := time.NewTicker(350 * time.Millisecond)
		stateTicker := time.NewTicker(4 * time.Second)
		defer ticker.Stop()
		defer stateTicker.Stop()

		for {
			select {
			case <-progressStop:
				return
			case <-workerCtx.Done():
				return
			case <-stateTicker.C:
				if statePath != "" {
					_ = state.Save(statePath)
				}
			case <-ticker.C:
				now := time.Now()
				interval := now.Sub(lastSpeedTime).Seconds()
				currBytes := atomic.LoadInt64(&bytesCounter)
				intervalBytes := currBytes - lastSpeedBytes
				speed := "0.0 MB/s"
				if interval > 0.05 && intervalBytes > 0 {
					mbps := (float64(intervalBytes) / (1024 * 1024)) / interval
					if mbps < 0.1 {
						kbps := (float64(intervalBytes) / 1024) / interval
						speed = fmt.Sprintf("%.1f KB/s", kbps)
					} else {
						speed = fmt.Sprintf("%.1f MB/s", mbps)
					}
				}
				lastSpeedBytes = currBytes
				lastSpeedTime = now

				completedP, totalP := coord.Progress()
				threads := int(atomic.LoadInt32(&activeThreads))
				if onProgress != nil {
					onProgress(currBytes, totalBytes, speed, threads, completedP, totalP)
				}
			}
		}
	}()

	// Worker logic
	for wID := 0; wID < concurrency; wID++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			atomic.AddInt32(&activeThreads, 1)
			defer atomic.AddInt32(&activeThreads, -1)

			buf := make([]byte, 64*1024)

			for {
				select {
				case <-workerCtx.Done():
					return
				default:
				}

				if coord.IsCompleted() {
					return
				}

				piece, ok := coord.NextPiece(workerID)
				if !ok {
					// No pending pieces right now, briefly wait for in-flight pieces to finish or stall
					select {
					case <-workerCtx.Done():
						return
					case <-time.After(200 * time.Millisecond):
						continue
					}
				}

				pieceErr := ad.downloadPiece(workerCtx, execURL, resolved, piece, targetFile, buf, &bytesCounter, coord)
				if pieceErr != nil {
					if errors.Is(pieceErr, context.Canceled) {
						return
					}
					coord.RequeuePiece(piece.Index)

					// If rate-limited (HTTP 429 / 503), throttle worker
					if errors.Is(pieceErr, ErrRateLimited) {
						time.Sleep(2 * time.Second)
					}
					continue
				}

				// Successfully downloaded piece
				coord.MarkCompleted(piece.Index)
				state.MarkBlockCompleted(piece.Index)
			}
		}(wID)
	}

	wg.Wait()
	close(progressStop)

	if workerCtx.Err() != nil && !coord.IsCompleted() {
		if errors.Is(workerCtx.Err(), context.Canceled) {
			if statePath != "" {
				_ = state.Save(statePath)
			}
			return nil, context.Canceled
		}
		return nil, workerCtx.Err()
	}

	select {
	case err := <-errChan:
		return nil, err
	default:
	}

	if !coord.IsCompleted() {
		return nil, errors.New("download incomplete: some segments could not be retrieved")
	}

	// Sniff magic bytes from initial 512 bytes on disk to refine file info
	peekBuf := make([]byte, 512)
	if n, _ := targetFile.ReadAt(peekBuf, 0); n > 0 {
		filename, mimeType = SniffMagicBytes(peekBuf[:n], filename, mimeType)
		fileInfo.Filename = filename
		fileInfo.MimeType = mimeType
	}

	// Final state save
	if statePath != "" {
		_ = state.Save(statePath)
	}

	if onProgress != nil {
		onProgress(totalBytes, totalBytes, "Idle", 0, coord.totalPieces, coord.totalPieces)
	}

	return fileInfo, nil
}

var (
	ErrNotAcceleratable = errors.New("remote resource does not support range acceleration")
	ErrRateLimited      = errors.New("remote host returned HTTP 429 or 503")
)

func (ad *AcceleratedDownloader) downloadPiece(
	ctx context.Context,
	urlStr string,
	resolved *ResolvedLink,
	piece *Piece,
	destFile *os.File,
	buf []byte,
	counter *int64,
	coord *PieceCoordinator,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return err
	}

	req.Header.Set("User-Agent", DefaultBrowserUserAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", piece.StartOffset, piece.EndOffset))

	if resolved != nil {
		if resolved.Referer != "" {
			req.Header.Set("Referer", resolved.Referer)
		}
		if resolved.AuthHeader != "" {
			req.Header.Set("Authorization", resolved.AuthHeader)
		}
	}

	resp, err := ad.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable {
		return ErrRateLimited
	}

	if resp.StatusCode != http.StatusPartialContent {
		// Server returned 200 OK or non-206: range request ignored
		return fmt.Errorf("server responded with unexpected status %d instead of 206 Partial Content", resp.StatusCode)
	}

	var bytesRead int64 = 0
	currentWriteOffset := piece.StartOffset

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			if _, wErr := destFile.WriteAt(buf[:n], currentWriteOffset); wErr != nil {
				return fmt.Errorf("disk write failure at offset %d: %w", currentWriteOffset, wErr)
			}
			currentWriteOffset += int64(n)
			bytesRead += int64(n)
			atomic.AddInt64(counter, int64(n))
			coord.TouchPiece(piece.Index)
		}

		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return rErr
		}
	}

	if bytesRead != piece.Length {
		return fmt.Errorf("piece length mismatch: expected %d bytes, received %d", piece.Length, bytesRead)
	}

	return nil
}
