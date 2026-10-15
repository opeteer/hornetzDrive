package upload

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestPoWChallenge_GenerateAndVerify(t *testing.T) {
	fileSize := int64(10 * 1024 * 1024) // 10MB file
	dummyFile := make([]byte, fileSize)
	_, _ = rand.Read(dummyFile)

	casHash := "a8f3b2c91d4e5f67890abcdef1234567890abcdef1234567890abcdef1234567"

	ch, err := GeneratePoWChallenge(casHash, fileSize)
	if err != nil {
		t.Fatalf("GeneratePoWChallenge failed: %v", err)
	}

	if len(ch.Offsets) != 3 {
		t.Fatalf("expected 3 offsets, got %d", len(ch.Offsets))
	}
	if ch.SampleSize != DefaultSampleSize {
		t.Fatalf("expected sample size %d, got %d", DefaultSampleSize, ch.SampleSize)
	}

	reader := bytes.NewReader(dummyFile)

	// Valid client computes valid HMAC
	validProof, err := ComputeSampleHMAC(reader, ch.Offsets, ch.SampleSize, ch.ChallengeNonce)
	if err != nil {
		t.Fatalf("ComputeSampleHMAC failed: %v", err)
	}

	if !VerifyPoW(reader, ch, validProof) {
		t.Fatalf("expected VerifyPoW to succeed with valid proof")
	}

	// Forged proof fails
	if VerifyPoW(reader, ch, "invalid_forged_proof_hex_string") {
		t.Fatalf("expected VerifyPoW to reject invalid proof")
	}

	// Mismatched data reader fails
	corruptedData := bytes.Clone(dummyFile)
	corruptedData[ch.Offsets[0]] ^= 0xFF
	badReader := bytes.NewReader(corruptedData)
	if VerifyPoW(badReader, ch, validProof) {
		t.Fatalf("expected VerifyPoW to reject proof when data does not match")
	}
}
