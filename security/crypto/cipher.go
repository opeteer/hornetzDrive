package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var (
	ErrInvalidKeySize   = errors.New("ztatic/crypto: invalid key size, must be 32 bytes for AES-256")
	ErrDecryptionFailed = errors.New("ztatic/crypto: decryption failed, invalid ciphertext or key")
)

// CipherSuite handles AES-256-GCM authenticated encryption for data security.
type CipherSuite struct {
	aead cipher.AEAD
}

// NewCipherSuite initializes a new AES-256-GCM cipher suite with the given 32-byte key.
func NewCipherSuite(key []byte) (*CipherSuite, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &CipherSuite{aead: aead}, nil
}

// Encrypt secures a plaintext string, returning a base64 URL-encoded ciphertext containing the nonce.
func (cs *CipherSuite) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", nil
	}

	nonce := make([]byte, cs.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Seal appends the ciphertext and authentication tag to the nonce
	ciphertext := cs.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt recovers plaintext from a base64 URL-encoded ciphertext.
func (cs *CipherSuite) Decrypt(encodedCiphertext string) (string, error) {
	if encodedCiphertext == "" {
		return "", nil
	}

	ciphertext, err := base64.RawURLEncoding.DecodeString(encodedCiphertext)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	nonceSize := cs.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrDecryptionFailed
	}

	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := cs.aead.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return "", ErrDecryptionFailed
	}

	return string(plaintext), nil
}
