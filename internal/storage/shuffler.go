package storage

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

type ChitinShuffler struct {
	CAS *CASEngine
}

// StartBackgroundWorker periodically shifts physical file timestamps and attributes
// to thwart access pattern correlation and forensic timeline reconstruction.
func (cs *ChitinShuffler) StartBackgroundWorker(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cs.ShufflePaths()
			}
		}
	}()
}

// ShufflePaths applies anti-forensic timestamp decorrelation across physical CAS files.
// By injecting randomized historical jitter rather than setting uniform timestamps,
// files cannot be forensically correlated by uniform mtime clusters (BUG-SEC-20).
func (cs *ChitinShuffler) ShufflePaths() {
	if cs.CAS == nil || cs.CAS.BaseDir == "" {
		return
	}
	fmt.Println("🛡️ Chitin Shuffler: Applying anti-forensic timeline jitter and inode obfuscation...")
	_ = filepath.Walk(cs.CAS.BaseDir, func(path string, info fs.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			var b [8]byte
			_, _ = rand.Read(b[:])
			// Jitter timestamps across past 7 days (min 1 hour, max 7 days)
			jitterSecs := 3600 + (binary.LittleEndian.Uint64(b[:]) % (7*24*3600 - 3600))
			jitteredTime := time.Now().Add(-time.Duration(jitterSecs) * time.Second)
			_ = os.Chtimes(path, jitteredTime, jitteredTime)
		}
		return nil
	})
	fmt.Println("🛡️ Chitin Shuffler: Anti-forensics timeline jitter complete.")
}
