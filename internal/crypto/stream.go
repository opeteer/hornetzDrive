package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// EncryptStream wraps an io.Writer. Every Write() call encrypts the payload
// as a discrete chunk in the Dynamo format: [4 bytes length][12 bytes nonce][ciphertext + tag]
type EncryptStream struct {
	w      io.Writer
	aesgcm cipher.AEAD
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
	return &EncryptStream{w: w, aesgcm: aesgcm}, nil
}

func (s *EncryptStream) Write(p []byte) (n int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, err
	}

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
