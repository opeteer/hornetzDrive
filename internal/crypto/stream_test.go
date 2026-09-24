package crypto

import (
	"bytes"
	"io"
	"testing"
)

func TestStreamEncryptionDecryption(t *testing.T) {
	vk := DummyVK()
	plaintext := []byte("secret cargo chunk payload for hornetz drive swarm vault")

	// Encrypt
	var encBuf bytes.Buffer
	encStream, err := NewEncryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("Failed to init encrypt stream: %v", err)
	}
	
	n, err := encStream.Write(plaintext)
	if err != nil || n != len(plaintext) {
		t.Fatalf("Write failed: %v", err)
	}

	// Decrypt
	decStream, err := NewDecryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("Failed to init decrypt stream: %v", err)
	}

	decrypted := make([]byte, len(plaintext))
	n, err = decStream.Read(decrypted)
	if err != nil {
		if err != io.EOF {
			t.Fatalf("Read failed: %v", err)
		}
	}

	if string(decrypted[:n]) != string(plaintext) {
		t.Fatalf("Decrypted text does not match. Got %s", string(decrypted[:n]))
	}
}
