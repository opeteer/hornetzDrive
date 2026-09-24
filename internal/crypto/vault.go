package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"golang.org/x/crypto/argon2"
	"io"
)

const (
	SaltSize     = 32
	NonceSize    = 12
	TagSize      = 16
	ArgonTime    = 3
	ArgonMemory  = 65536
	ArgonThreads = 4
	KeySize      = 32
)

// DeriveMEK derives the Master Encryption Key using Argon2id.
func DeriveMEK(password []byte, salt []byte) []byte {
	return argon2.IDKey(password, salt, ArgonTime, ArgonMemory, ArgonThreads, KeySize)
}

// EncryptBlock encrypts a single block of data entirely in memory.
func EncryptBlock(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, data, nil)
	// Dynamo appends nonce to ciphertext, let's prepend nonce
	result := append(nonce, ciphertext...)
	return result, nil
}

// DecryptBlock decrypts a single block of data.
func DecryptBlock(data []byte, key []byte) ([]byte, error) {
	if len(data) < NonceSize+TagSize {
		return nil, errors.New("data too short")
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, nonce, ciphertext, nil)
}
