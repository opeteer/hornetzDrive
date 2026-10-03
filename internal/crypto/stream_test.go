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

func TestDecryptStream_BoundsChecks(t *testing.T) {
	vk := DummyVK()

	// 1. Chunk length exceeds MaxChunkSize (50MB)
	var overBuf bytes.Buffer
	// Write length 60MB: 60 * 1024 * 1024 = 62914560 (0x03C00000)
	overBuf.Write([]byte{0x03, 0xC0, 0x00, 0x00})
	overBuf.Write(make([]byte, 100))

	decStream, err := NewDecryptStream(&overBuf, vk)
	if err != nil {
		t.Fatalf("NewDecryptStream failed: %v", err)
	}

	buf := make([]byte, 1024)
	_, err = decStream.Read(buf)
	if err == nil {
		t.Fatalf("Expected error when chunk size exceeds MaxChunkSize")
	}

	// 2. Chunk length smaller than TagSize (16 bytes)
	var underBuf bytes.Buffer
	underBuf.Write([]byte{0x00, 0x00, 0x00, 0x08}) // 8 bytes < 16
	underBuf.Write(make([]byte, 8))

	decStream2, err := NewDecryptStream(&underBuf, vk)
	if err != nil {
		t.Fatalf("NewDecryptStream failed: %v", err)
	}

	_, err = decStream2.Read(buf)
	if err == nil {
		t.Fatalf("Expected error when chunk size is smaller than TagSize")
	}
}

func TestDecryptStream_SeekTo(t *testing.T) {
	vk := DummyVK()
	// Write three chunks of 100 bytes each
	var encBuf bytes.Buffer
	encStream, err := NewEncryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("NewEncryptStream failed: %v", err)
	}

	c1 := bytes.Repeat([]byte("A"), 100)
	c2 := bytes.Repeat([]byte("B"), 100)
	c3 := bytes.Repeat([]byte("C"), 100)

	_, _ = encStream.Write(c1)
	_, _ = encStream.Write(c2)
	_, _ = encStream.Write(c3)

	// Seek to offset 250 (inside chunk 3) using bytes.Reader which implements io.ReadSeeker
	reader := bytes.NewReader(encBuf.Bytes())
	decStream, err := NewDecryptStream(reader, vk)
	if err != nil {
		t.Fatalf("NewDecryptStream failed: %v", err)
	}

	if err := decStream.SeekTo(250); err != nil {
		t.Fatalf("SeekTo failed: %v", err)
	}

	remaining := make([]byte, 50)
	n, err := io.ReadFull(decStream, remaining)
	if err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}
	if n != 50 {
		t.Fatalf("Expected 50 bytes, got %d", n)
	}
	if !bytes.Equal(remaining, bytes.Repeat([]byte("C"), 50)) {
		t.Fatalf("Expected 50 'C' bytes, got %s", string(remaining))
	}
}

func TestDecryptStream_SeekRewindAndMultiSeek(t *testing.T) {
	vk := DummyVK()
	var encBuf bytes.Buffer
	encStream, err := NewEncryptStream(&encBuf, vk)
	if err != nil {
		t.Fatalf("NewEncryptStream failed: %v", err)
	}

	_, _ = encStream.Write([]byte("CHUNK1_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
	_, _ = encStream.Write([]byte("CHUNK2_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"))
	_, _ = encStream.Write([]byte("CHUNK3_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"))

	reader := bytes.NewReader(encBuf.Bytes())
	decStream, err := NewDecryptStream(reader, vk)
	if err != nil {
		t.Fatalf("NewDecryptStream failed: %v", err)
	}

	// 1. Seek to offset 10 and read 5 bytes
	if err := decStream.SeekTo(10); err != nil {
		t.Fatalf("SeekTo(10) failed: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(decStream, buf); err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	// 2. Rewind to offset 0 and read first 5 bytes
	if err := decStream.SeekTo(0); err != nil {
		t.Fatalf("SeekTo(0) failed: %v", err)
	}
	buf0 := make([]byte, 5)
	if _, err := io.ReadFull(decStream, buf0); err != nil {
		t.Fatalf("ReadFull after SeekTo(0) failed: %v", err)
	}
	if string(buf0) != "CHUNK" {
		t.Fatalf("SeekTo(0) failed to rewind: expected 'CHUNK', got %q", string(buf0))
	}

	// 3. Seek forward across chunks (offset 60)
	if err := decStream.SeekTo(60); err != nil {
		t.Fatalf("SeekTo(60) failed: %v", err)
	}
	buf60 := make([]byte, 5)
	if _, err := io.ReadFull(decStream, buf60); err != nil {
		t.Fatalf("ReadFull after SeekTo(60) failed: %v", err)
	}
	if string(buf60) != "BBBBB" {
		t.Fatalf("SeekTo(60) failed: expected 'BBBBB', got %q", string(buf60))
	}

	// 4. Seek backward to offset 20
	if err := decStream.SeekTo(20); err != nil {
		t.Fatalf("SeekTo(20) backward failed: %v", err)
	}
	buf20 := make([]byte, 5)
	if _, err := io.ReadFull(decStream, buf20); err != nil {
		t.Fatalf("ReadFull after SeekTo(20) failed: %v", err)
	}
	if string(buf20) != "AAAAA" {
		t.Fatalf("SeekTo(20) backward failed: expected 'AAAAA', got %q", string(buf20))
	}
}

