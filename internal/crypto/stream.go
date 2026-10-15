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
	w         io.Writer
	aesgcm    cipher.AEAD
	key       []byte
	packetBuf []byte // Reusable packet buffer for [4 bytes len][12 bytes nonce][ciphertext + tag]
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

	// Format: [4 bytes chunk_size][12 bytes nonce][ciphertext + tag]
	neededCap := 4 + NonceSize + len(p) + TagSize
	if cap(s.packetBuf) < neededCap {
		s.packetBuf = make([]byte, neededCap)
	} else {
		s.packetBuf = s.packetBuf[:neededCap]
	}

	chunkLen := uint32(len(p) + TagSize)
	binary.BigEndian.PutUint32(s.packetBuf[0:4], chunkLen)
	copy(s.packetBuf[4:16], nonce)

	// Encrypt directly into the pre-allocated slice without extra heap allocations
	s.aesgcm.Seal(s.packetBuf[16:16], nonce, p, nil)

	// Framed single-pass I/O write (1 syscall instead of 3)
	if _, err := s.w.Write(s.packetBuf[:neededCap]); err != nil {
		return 0, err
	}

	return len(p), nil
}

// DecryptStream wraps an io.Reader assuming it's in the Dynamo format.
type DecryptStream struct {
	r         io.Reader
	aesgcm    cipher.AEAD
	buf       []byte              // Buffer for decrypted chunks not yet consumed by caller
	hdrBuf    [4 + NonceSize]byte // Framed 16-byte header: [4 bytes length][12 bytes nonce]
	cipherBuf []byte
	plainBuf  []byte
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

	// 2. Read framed chunk header (16 bytes: 4 bytes length + 12 bytes nonce) in a single read call
	if _, err := io.ReadFull(s.r, s.hdrBuf[:]); err != nil {
		return 0, err
	}
	chunkLen := binary.BigEndian.Uint32(s.hdrBuf[0:4])
	const MaxChunkSize = 50 * 1024 * 1024 // 50 MB upper limit to protect against OOM
	if chunkLen < TagSize || chunkLen > MaxChunkSize {
		return 0, errors.New("invalid or excessive chunk length")
	}
	nonce := s.hdrBuf[4:16]

	// 3. Read ciphertext into reusable buffer
	if cap(s.cipherBuf) < int(chunkLen) {
		s.cipherBuf = make([]byte, chunkLen)
	} else {
		s.cipherBuf = s.cipherBuf[:chunkLen]
	}
	if _, err := io.ReadFull(s.r, s.cipherBuf); err != nil {
		return 0, err
	}

	// 4. Decrypt and authenticate reusing plainBuf capacity
	plainCap := int(chunkLen - TagSize)
	if cap(s.plainBuf) < plainCap {
		s.plainBuf = make([]byte, 0, plainCap)
	}
	plaintext, err := s.aesgcm.Open(s.plainBuf[:0], nonce, s.cipherBuf, nil)
	if err != nil {
		return 0, errors.New("authentication failed")
	}

	// 5. Copy as much as fits into p, and buffer the rest
	n = copy(p, plaintext)
	if n < len(plaintext) {
		s.buf = plaintext[n:]
	}
	return n, nil
}

// PreloadFirstChunk attempts to decrypt the first chunk of the stream into s.buf without advancing the readable stream position.
// This allows verifying encryption keys and chunk integrity before committing HTTP response headers with zero heap reallocations.
func (s *DecryptStream) PreloadFirstChunk() error {
	if len(s.buf) > 0 {
		return nil
	}

	// Read framed chunk header (16 bytes: 4 bytes length + 12 bytes nonce)
	if _, err := io.ReadFull(s.r, s.hdrBuf[:]); err != nil {
		return err
	}
	chunkLen := binary.BigEndian.Uint32(s.hdrBuf[0:4])
	const MaxChunkSize = 50 * 1024 * 1024
	if chunkLen < TagSize || chunkLen > MaxChunkSize {
		return errors.New("invalid or excessive chunk length")
	}
	nonce := s.hdrBuf[4:16]

	if cap(s.cipherBuf) < int(chunkLen) {
		s.cipherBuf = make([]byte, chunkLen)
	} else {
		s.cipherBuf = s.cipherBuf[:chunkLen]
	}
	if _, err := io.ReadFull(s.r, s.cipherBuf); err != nil {
		return err
	}

	plainCap := int(chunkLen - TagSize)
	if cap(s.plainBuf) < plainCap {
		s.plainBuf = make([]byte, 0, plainCap)
	}
	plaintext, err := s.aesgcm.Open(s.plainBuf[:0], nonce, s.cipherBuf, nil)
	if err != nil {
		return errors.New("authentication failed")
	}

	// Directly assign decrypted plaintext to buffer with zero extra allocations
	s.buf = plaintext
	return nil
}

// SeekTo skips forward to the requested plaintext byte offset in the stream.
// If the underlying reader implements io.ReadSeeker, preceding chunks are skipped
// on disk without decrypting them, eliminating sequential decryption DoS.
func (s *DecryptStream) SeekTo(offset int64) error {
	if offset < 0 {
		return errors.New("negative offset not supported")
	}
	s.buf = nil

	seeker, isSeeker := s.r.(io.ReadSeeker)
	if isSeeker {
		if _, err := seeker.Seek(0, io.SeekStart); err != nil {
			return err
		}
	} else if offset == 0 {
		return nil
	}

	if offset == 0 {
		return nil
	}

	if !isSeeker {
		// Fallback to sequential discard
		_, err := io.CopyN(io.Discard, s, offset)
		return err
	}

	// Optimization: If reader implements io.ReaderAt (e.g. *os.File),
	// scan chunk lengths via ReadAt without kernel lseek syscalls on each iteration.
	if readerAt, isReaderAt := s.r.(io.ReaderAt); isReaderAt {
		currentOffset := int64(0)
		diskPos := int64(0)
		for currentOffset < offset {
			var lenBuf [4]byte
			if _, err := readerAt.ReadAt(lenBuf[:], diskPos); err != nil {
				return err
			}
			chunkLen := binary.BigEndian.Uint32(lenBuf[:])
			if chunkLen < TagSize || chunkLen > 50*1024*1024 {
				return errors.New("invalid or excessive chunk length")
			}
			plainLen := int64(chunkLen - TagSize)
			if currentOffset+plainLen <= offset {
				// Advance disk pointer past [4-byte len][12-byte nonce][ciphertext + tag]
				diskPos += 4 + int64(NonceSize) + int64(chunkLen)
				currentOffset += plainLen
			} else {
				// Target chunk found! Seek directly to this chunk in a single syscall
				if _, err := seeker.Seek(diskPos, io.SeekStart); err != nil {
					return err
				}
				// Read framed header (16 bytes)
				if _, err := io.ReadFull(s.r, s.hdrBuf[:]); err != nil {
					return err
				}
				nonce := s.hdrBuf[4:16]
				if cap(s.cipherBuf) < int(chunkLen) {
					s.cipherBuf = make([]byte, chunkLen)
				} else {
					s.cipherBuf = s.cipherBuf[:chunkLen]
				}
				if _, err := io.ReadFull(s.r, s.cipherBuf); err != nil {
					return err
				}
				plainCap := int(chunkLen - TagSize)
				if cap(s.plainBuf) < plainCap {
					s.plainBuf = make([]byte, 0, plainCap)
				}
				plaintext, err := s.aesgcm.Open(s.plainBuf[:0], nonce, s.cipherBuf, nil)
				if err != nil {
					return errors.New("authentication failed")
				}
				skipInChunk := offset - currentOffset
				s.buf = plaintext[skipInChunk:]
				return nil
			}
		}
		return nil
	}

	// Fallback for ReadSeekers without ReaderAt
	currentOffset := int64(0)
	for currentOffset < offset {
		var lenBuf [4]byte
		if _, err := io.ReadFull(s.r, lenBuf[:]); err != nil {
			return err
		}
		chunkLen := binary.BigEndian.Uint32(lenBuf[:])
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
			// The requested offset begins inside this chunk. Read nonce (12 bytes)
			if _, err := io.ReadFull(s.r, s.hdrBuf[4:16]); err != nil {
				return err
			}
			nonce := s.hdrBuf[4:16]
			if cap(s.cipherBuf) < int(chunkLen) {
				s.cipherBuf = make([]byte, chunkLen)
			} else {
				s.cipherBuf = s.cipherBuf[:chunkLen]
			}
			if _, err := io.ReadFull(s.r, s.cipherBuf); err != nil {
				return err
			}
			plainCap := int(chunkLen - TagSize)
			if cap(s.plainBuf) < plainCap {
				s.plainBuf = make([]byte, 0, plainCap)
			}
			plaintext, err := s.aesgcm.Open(s.plainBuf[:0], nonce, s.cipherBuf, nil)
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
