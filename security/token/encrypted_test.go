package token

import (
	"strings"
	"testing"

	"ztatic-go-framework/security/crypto"
)

func TestEncryptedEngine_SignAndVerify(t *testing.T) {
	key := []byte("01234567890123456789012345678901") // 32 bytes
	cs, err := crypto.NewCipherSuite(key)
	if err != nil {
		t.Fatal(err)
	}

	engine, err := NewEncryptedEngine(cs)
	if err != nil {
		t.Fatal(err)
	}

	claims := &Claims{
		StandardClaims: StandardClaims{
			Subject: "user-456",
		},
		Roles: []string{"manager"},
	}

	tokenStr, err := engine.Sign(claims)
	if err != nil {
		t.Fatalf("failed to sign encrypted token: %v", err)
	}

	if !strings.HasPrefix(tokenStr, EncryptedPrefix) {
		t.Fatalf("expected prefix %s, got: %s", EncryptedPrefix, tokenStr)
	}

	tok, err := engine.Verify(tokenStr)
	if err != nil {
		t.Fatalf("failed to verify encrypted token: %v", err)
	}

	if tok.Claims.Subject != "user-456" {
		t.Errorf("expected subject user-456, got: %s", tok.Claims.Subject)
	}
	if !tok.Claims.HasRole("manager") {
		t.Errorf("expected manager role")
	}

	// Tampered token test
	tampered := tokenStr[:len(tokenStr)-4] + "AAAA"
	_, err = engine.Verify(tampered)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature on tampered ciphertext, got: %v", err)
	}
}
