package crypto

import (
	"bytes"
	"testing"
)

func TestArgon2idDeriveMEK(t *testing.T) {
	password := []byte("master_swarm_password_2026")
	salt := []byte("0123456789abcdef0123456789abcdef")

	key1 := DeriveMEK(password, salt)
	if len(key1) != 32 {
		t.Fatalf("Expected 32-byte key, got %d", len(key1))
	}

	// Determinism test
	key2 := DeriveMEK(password, salt)
	if !bytes.Equal(key1, key2) {
		t.Fatalf("DeriveMEK is not deterministic")
	}

	// Salt variation test
	salt2 := []byte("1123456789abcdef0123456789abcdef")
	key3 := DeriveMEK(password, salt2)
	if bytes.Equal(key1, key3) {
		t.Fatalf("Different salts produced identical keys")
	}
}

func TestBlockEncryptionDecryption(t *testing.T) {
	key := DummyVK()
	plaintext := []byte("top secret swarm vault payload")

	encrypted, err := EncryptBlock(plaintext, key)
	if err != nil {
		t.Fatalf("EncryptBlock failed: %v", err)
	}

	decrypted, err := DecryptBlock(encrypted, key)
	if err != nil {
		t.Fatalf("DecryptBlock failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted block mismatch: got %s, expected %s", string(decrypted), string(plaintext))
	}

	// Test Tampering
	encrypted[len(encrypted)-1] ^= 0xFF
	_, err = DecryptBlock(encrypted, key)
	if err == nil {
		t.Fatalf("DecryptBlock should fail on corrupted ciphertext")
	}
}
