package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// EncryptStream wraps an io.Writer. Every Write() call encrypts the payload
// as a discrete chunk in the Dynamo format: [4 bytes length][12 bytes nonce][ciphertext + tag]
type EncryptStream struct {
	w      io.Writer
	aesgcm cipher.AEAD
	key    []byte
}

func NewEncryptStream(w io.Writer, key []byte) (*EncryptStream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return &EncryptStream{w: w, aesgcm: aesgcm, key: keyCopy}, nil
}

func (s *EncryptStream) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Convergent deterministic nonce derivation using HMAC-SHA256(key, chunk)
	// Ensures identical plaintext produces identical ciphertext and CAS hash for deduplication
	mac := hmac.New(sha256.New, s.key)
	mac.Write(p)
	nonce := mac.Sum(nil)[:NonceSize]

	ciphertext := s.aesgcm.Seal(nil, nonce, p, nil)

	// Format: [4 bytes chunk_size][12 bytes nonce][ciphertext]
	// Note: Dynamo uses 4 bytes to store the length of (ciphertext)
	chunkLen := uint32(len(ciphertext))
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, chunkLen)

	if _, err := s.w.Write(lenBuf); err != nil {
		return 0, err
	}
	if _, err := s.w.Write(nonce); err != nil {
		return 0, err
	}
	if _, err := s.w.Write(ciphertext); err != nil {
		return 0, err
	}

	return len(p), nil
}

// DecryptStream wraps an io.Reader assuming it's in the Dynamo format.
type DecryptStream struct {
	r      io.Reader
	aesgcm cipher.AEAD
	buf    []byte // Buffer for decrypted chunks not yet consumed by caller
}

func NewDecryptStream(r io.Reader, key []byte) (*DecryptStream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &DecryptStream{r: r, aesgcm: aesgcm}, nil
}

func (s *DecryptStream) Read(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	// 1. Drain existing plaintext buffer first
	if len(s.buf) > 0 {
		n = copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}

	// 2. Read length of next chunk (4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(s.r, lenBuf); err != nil {
		return 0, err
	}
	chunkLen := binary.BigEndian.Uint32(lenBuf)
	const MaxChunkSize = 50 * 1024 * 1024 // 50 MB upper limit to protect against OOM
	if chunkLen < TagSize || chunkLen > MaxChunkSize {
		return 0, errors.New("invalid or excessive chunk length")
	}

	// 3. Read nonce (12 bytes)
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(s.r, nonce); err != nil {
		return 0, err
	}

	// 4. Read ciphertext
	ciphertext := make([]byte, chunkLen)
	if _, err := io.ReadFull(s.r, ciphertext); err != nil {
		return 0, err
	}

	// 5. Decrypt and authenticate
	plaintext, err := s.aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return 0, errors.New("authentication failed")
	}

	// 6. Copy as much as fits into p, and buffer the rest
	n = copy(p, plaintext)
	if n < len(plaintext) {
		s.buf = plaintext[n:]
	}
	return n, nil
}

// SeekTo skips forward to the requested plaintext byte offset in the stream.
// If the underlying reader implements io.ReadSeeker, preceding chunks are skipped
// on disk without decrypting them, eliminating sequential decryption DoS.
func (s *DecryptStream) SeekTo(offset int64) error {
	if offset < 0 {
		return errors.New("negative offset not supported")
	}
	s.buf = nil
	if offset == 0 {
		return nil
	}

	seeker, isSeeker := s.r.(io.ReadSeeker)
	if !isSeeker {
		// Fallback to sequential discard
		_, err := io.CopyN(io.Discard, s, offset)
		return err
	}

	currentOffset := int64(0)
	for currentOffset < offset {
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(s.r, lenBuf); err != nil {
			return err
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf)
		if chunkLen < TagSize || chunkLen > 50*1024*1024 {
			return errors.New("invalid or excessive chunk length")
		}
		plainLen := int64(chunkLen - TagSize)
		if currentOffset+plainLen <= offset {
			// Skip this entire chunk on disk without decrypting
			if _, err := seeker.Seek(int64(NonceSize)+int64(chunkLen), io.SeekCurrent); err != nil {
				return err
			}
			currentOffset += plainLen
		} else {
			// The requested offset begins inside this chunk. Decrypt this chunk:
			nonce := make([]byte, NonceSize)
			if _, err := io.ReadFull(s.r, nonce); err != nil {
				return err
			}
			ciphertext := make([]byte, chunkLen)
			if _, err := io.ReadFull(s.r, ciphertext); err != nil {
				return err
			}
			plaintext, err := s.aesgcm.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				return errors.New("authentication failed")
			}
			skipInChunk := offset - currentOffset
			s.buf = plaintext[skipInChunk:]
			break
		}
	}
	return nil
}
