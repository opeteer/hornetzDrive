package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCipherSuite_EncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	cs, err := NewCipherSuite(key)
	if err != nil {
		t.Fatalf("failed to create cipher suite: %v", err)
	}

	plaintext := "SensitiveSecretData123!@#"
	ciphertext, err := cs.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if ciphertext == plaintext {
		t.Errorf("ciphertext should not match plaintext")
	}

	recovered, err := cs.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if recovered != plaintext {
		t.Errorf("expected recovered plaintext %q, got %q", plaintext, recovered)
	}
}

func TestCipherSuite_InvalidKeySize(t *testing.T) {
	invalidKey := make([]byte, 16) // Only 16 bytes instead of 32
	_, err := NewCipherSuite(invalidKey)
	if err != ErrInvalidKeySize {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestCipherSuite_CorruptedCiphertext(t *testing.T) {
	key := bytes.Repeat([]byte("a"), 32)
	cs, _ := NewCipherSuite(key)

	_, err := cs.Decrypt("invalid-base64-payload!!!")
	if err != ErrDecryptionFailed {
		t.Errorf("expected ErrDecryptionFailed for bad ciphertext, got %v", err)
	}
}
