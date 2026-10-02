package token

import (
	"encoding/json"
	"strings"

	"ztatic-go-framework/security/crypto"
)

const (
	EncryptedPrefix   = "zt1.enc."
	AlgorithmA256GCM  Algorithm = "A256GCM"
)

// EncryptedEngine provides authenticated AEAD encrypted tokens using AES-256-GCM.
// Encrypted tokens guarantee both confidentiality (claims cannot be inspected by client)
// and authenticity (tampering triggers decryption failure).
type EncryptedEngine struct {
	cipher *crypto.CipherSuite
}

// NewEncryptedEngine creates an engine using an initialized AES-256-GCM cipher suite.
func NewEncryptedEngine(cs *crypto.CipherSuite) (*EncryptedEngine, error) {
	if cs == nil {
		return nil, ErrInvalidKey
	}
	return &EncryptedEngine{cipher: cs}, nil
}

// Algorithm returns A256GCM.
func (e *EncryptedEngine) Algorithm() Algorithm {
	return AlgorithmA256GCM
}

// Sign serializes the claims to JSON and encrypts them with AES-256-GCM.
func (e *EncryptedEngine) Sign(claims *Claims) (string, error) {
	if claims == nil {
		return "", ErrInvalidToken
	}

	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	ciphertext, err := e.cipher.Encrypt(string(claimsBytes))
	if err != nil {
		return "", err
	}

	return EncryptedPrefix + ciphertext, nil
}

// Verify decrypts and parses an encrypted token into a verified Token entity.
func (e *EncryptedEngine) Verify(tokenString string) (*Token, error) {
	if !strings.HasPrefix(tokenString, EncryptedPrefix) {
		return nil, ErrInvalidToken
	}

	ciphertext := strings.TrimPrefix(tokenString, EncryptedPrefix)
	plaintext, err := e.cipher.Decrypt(ciphertext)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	var claims Claims
	if err := json.Unmarshal([]byte(plaintext), &claims); err != nil {
		return nil, ErrInvalidToken
	}

	return &Token{
		Raw: tokenString,
		Header: Header{
			Alg: AlgorithmA256GCM,
			Typ: "ENC",
		},
		Claims: &claims,
	}, nil
}
