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

func TestStream_SmallBufferReads(t *testing.T) {
	vk := DummyVK()
	// Large plaintext: 128 KB
	original := make([]byte, 128*1024)
	for i := range original {
		original[i] = byte(i % 256)
	}

	var encBuf bytes.Buffer
	encStream, err := NewEncryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("NewEncryptStream failed: %v", err)
	}

	// Write in two 64 KB chunks
	if _, err := encStream.Write(original[:64*1024]); err != nil {
		t.Fatalf("Write chunk 1 failed: %v", err)
	}
	if _, err := encStream.Write(original[64*1024:]); err != nil {
		t.Fatalf("Write chunk 2 failed: %v", err)
	}

	decStream, err := NewDecryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("NewDecryptStream failed: %v", err)
	}

	// Read out using standard io.Copy with a 32 KB buffer (like io.Copy uses)
	var outBuf bytes.Buffer
	transferBuf := make([]byte, 32*1024)
	written, err := io.CopyBuffer(&outBuf, decStream, transferBuf)
	if err != nil {
		t.Fatalf("io.CopyBuffer failed: %v", err)
	}

	if int(written) != len(original) {
		t.Fatalf("Expected %d bytes decrypted, got %d", len(original), written)
	}
	if !bytes.Equal(outBuf.Bytes(), original) {
		t.Fatalf("Decrypted bytes do not match original payload")
	}
}

func TestStream_TinyBufferReads(t *testing.T) {
	vk := DummyVK()
	payload := []byte("The quick brown fox jumps over the lazy dog. 1234567890! Special cryptography test string.")

	var encBuf bytes.Buffer
	encStream, err := NewEncryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("NewEncryptStream failed: %v", err)
	}
	if _, err := encStream.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	decStream, err := NewDecryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("NewDecryptStream failed: %v", err)
	}

	// Read in tiny 7-byte slices
	var result []byte
	tinyBuf := make([]byte, 7)
	for {
		n, err := decStream.Read(tinyBuf)
		if n > 0 {
			result = append(result, tinyBuf[:n]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read with tiny buffer failed: %v", err)
		}
	}

	if !bytes.Equal(result, payload) {
		t.Fatalf("Expected %q, got %q", string(payload), string(result))
	}
}
