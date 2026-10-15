package upload

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"time"
)

// PoWChallenge represents a cryptographic challenge issued to a client claiming file ownership.
type PoWChallenge struct {
	CasHash        string
	ChallengeNonce string
	Offsets        []int64
	SampleSize     int64
	ExpiresAt      time.Time
}

var (
	powMu     sync.RWMutex
	powStore  = make(map[string]*PoWChallenge)
)

const (
	DefaultSampleSize = 1024
	ChallengeTTL      = 5 * time.Minute
)

// GeneratePoWChallenge creates a non-forgeable challenge for the given CAS hash and file size.
func GeneratePoWChallenge(casHash string, fileSize int64) (*PoWChallenge, error) {
	if casHash == "" {
		return nil, errors.New("casHash cannot be empty")
	}

	sampleSize := int64(DefaultSampleSize)
	if fileSize > 0 && fileSize < sampleSize {
		sampleSize = fileSize
	}

	nonceBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonceBytes); err != nil {
		return nil, err
	}
	nonce := hex.EncodeToString(nonceBytes)

	// If file is very small or 0 bytes, single offset 0 is sufficient
	maxOffset := fileSize - sampleSize
	if maxOffset <= 0 {
		ch := &PoWChallenge{
			CasHash:        casHash,
			ChallengeNonce: nonce,
			Offsets:        []int64{0},
			SampleSize:     sampleSize,
			ExpiresAt:      time.Now().Add(ChallengeTTL),
		}
		SavePoWChallenge(ch)
		return ch, nil
	}

	// Derive 3 pseudorandom offsets deterministically from the nonce and casHash
	h := sha256.Sum256([]byte(nonce + ":" + casHash))
	o1 := (int64(binary.BigEndian.Uint64(h[0:8])) & 0x7fffffffffffffff) % maxOffset
	o2 := (int64(binary.BigEndian.Uint64(h[8:16])) & 0x7fffffffffffffff) % maxOffset
	o3 := (int64(binary.BigEndian.Uint64(h[16:24])) & 0x7fffffffffffffff) % maxOffset

	ch := &PoWChallenge{
		CasHash:        casHash,
		ChallengeNonce: nonce,
		Offsets:        []int64{o1, o2, o3},
		SampleSize:     sampleSize,
		ExpiresAt:      time.Now().Add(ChallengeTTL),
	}
	SavePoWChallenge(ch)
	return ch, nil
}

// SavePoWChallenge stores a challenge in memory.
func SavePoWChallenge(ch *PoWChallenge) {
	powMu.Lock()
	defer powMu.Unlock()
	powStore[ch.ChallengeNonce] = ch
}

// GetPoWChallenge retrieves and validates an active challenge.
func GetPoWChallenge(nonce string) (*PoWChallenge, bool) {
	powMu.RLock()
	defer powMu.RUnlock()
	ch, ok := powStore[nonce]
	if !ok || time.Now().After(ch.ExpiresAt) {
		return nil, false
	}
	return ch, true
}

// DeletePoWChallenge removes a completed or consumed challenge.
func DeletePoWChallenge(nonce string) {
	powMu.Lock()
	defer powMu.Unlock()
	delete(powStore, nonce)
}

// ComputeSampleHMAC calculates HMAC-SHA256 across the specified byte ranges of a seeker.
func ComputeSampleHMAC(r io.ReadSeeker, offsets []int64, sampleSize int64, nonce string) (string, error) {
	mac := hmac.New(sha256.New, []byte(nonce))
	buf := make([]byte, sampleSize)

	for _, offset := range offsets {
		if _, err := r.Seek(offset, io.SeekStart); err != nil {
			return "", err
		}
		n, err := io.ReadFull(r, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			return "", err
		}
		mac.Write(buf[:n])
	}

	return hex.EncodeToString(mac.Sum(nil)), nil
}

// VerifyPoW verifies that client proof matches expected HMAC computed from the raw file reader.
func VerifyPoW(r io.ReadSeeker, ch *PoWChallenge, clientProof string) bool {
	expected, err := ComputeSampleHMAC(r, ch.Offsets, ch.SampleSize, ch.ChallengeNonce)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(clientProof)) == 1
}
