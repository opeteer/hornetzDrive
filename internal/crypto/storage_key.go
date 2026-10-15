package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var (
	standardKeyMu   sync.RWMutex
	standardKey     []byte
	defaultInitOnce sync.Once
)

// InitStandardStorageKey initializes the master key used for standard (non-vault) storage files.
// If configuredKey is non-empty, a 32-byte key is derived from it.
// Otherwise, it loads or generates a 32-byte key file at filepath.Join(storageDir, ".master_key").
func InitStandardStorageKey(configuredKey string, storageDir string) ([]byte, error) {
	standardKeyMu.Lock()
	defer standardKeyMu.Unlock()

	if configuredKey != "" {
		h := sha256.Sum256([]byte(configuredKey))
		k := make([]byte, 32)
		copy(k, h[:])
		standardKey = k
		return copyKey(standardKey), nil
	}

	if storageDir == "" {
		storageDir = "storage"
	}
	_ = os.MkdirAll(storageDir, 0700)
	keyPath := filepath.Join(storageDir, ".master_key")

	if data, err := os.ReadFile(keyPath); err == nil && len(data) == 32 {
		standardKey = data
		return copyKey(standardKey), nil
	}

	newKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, newKey); err != nil {
		return nil, errors.New("failed to generate secure random master key: " + err.Error())
	}

	if err := os.WriteFile(keyPath, newKey, 0600); err != nil {
		// If unable to persist to disk (e.g. read-only filesystem), keep in memory
		standardKey = newKey
		return copyKey(standardKey), nil
	}

	standardKey = newKey
	return copyKey(standardKey), nil
}

// GetStandardStorageKey returns a copy of the active 32-byte master key for standard files.
func GetStandardStorageKey() []byte {
	standardKeyMu.RLock()
	k := standardKey
	standardKeyMu.RUnlock()

	if len(k) == 32 {
		return copyKey(k)
	}

	defaultInitOnce.Do(func() {
		_, _ = InitStandardStorageKey("", "storage")
	})

	standardKeyMu.RLock()
	defer standardKeyMu.RUnlock()
	return copyKey(standardKey)
}

// SetStandardStorageKeyForTesting overrides the master key for unit tests.
func SetStandardStorageKeyForTesting(key []byte) {
	standardKeyMu.Lock()
	defer standardKeyMu.Unlock()
	standardKey = copyKey(key)
}

func copyKey(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// LegacyStorageKey is the hardcoded fallback key used prior to BUG-SEC-03.
var LegacyStorageKey = []byte("0123456789abcdef0123456789abcdef")

// GetLegacyStorageKey returns the legacy 32-byte key for backwards-compatibility.
func GetLegacyStorageKey() []byte {
	return copyKey(LegacyStorageKey)
}

