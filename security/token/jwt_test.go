package token

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestHMACEngine_SignAndVerify(t *testing.T) {
	secret := []byte("01234567890123456789012345678901") // 32 bytes

	for _, alg := range []Algorithm{HS256, HS384, HS512} {
		t.Run(string(alg), func(t *testing.T) {
			engine, err := NewHMACEngine(alg, secret)
			if err != nil {
				t.Fatalf("failed to create engine: %v", err)
			}

			claims := &Claims{
				StandardClaims: StandardClaims{
					Subject: "user-123",
					Issuer:  "ztatic-auth",
				},
				Roles: []string{"admin"},
			}

			rawToken, err := engine.Sign(claims)
			if err != nil {
				t.Fatalf("failed to sign token: %v", err)
			}

			tok, err := engine.Verify(rawToken)
			if err != nil {
				t.Fatalf("failed to verify token: %v", err)
			}

			if tok.Claims.Subject != "user-123" {
				t.Errorf("expected subject user-123, got: %s", tok.Claims.Subject)
			}
			if !tok.Claims.HasRole("admin") {
				t.Errorf("expected role admin")
			}
		})
	}
}

func TestHMACEngine_KeyLengthEnforcement(t *testing.T) {
	shortSecret := []byte("short-secret")
	_, err := NewHMACEngine(HS256, shortSecret)
	if err != ErrInvalidKey {
		t.Fatalf("expected ErrInvalidKey for secret under 32 bytes, got: %v", err)
	}
}

func TestHMACEngine_SignatureTampering(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	engine, err := NewHMACEngine(HS256, secret)
	if err != nil {
		t.Fatal(err)
	}

	rawToken, err := engine.Sign(&Claims{StandardClaims: StandardClaims{Subject: "user-1"}})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(rawToken, ".")

	// Tamper payload
	tamperedPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-hacked"}`))
	tamperedToken := parts[0] + "." + tamperedPayload + "." + parts[2]

	_, err = engine.Verify(tamperedToken)
	if err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature on tampered payload, got: %v", err)
	}

	// Tamper signature
	tamperedSigToken := parts[0] + "." + parts[1] + ".invalid-sig"
	_, err = engine.Verify(tamperedSigToken)
	if err == nil {
		t.Fatalf("expected error on tampered signature")
	}
}

func TestHMACEngine_AlgorithmConfusionRejection(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	engine, _ := NewHMACEngine(HS256, secret)

	// 1. "none" algorithm attack header
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-admin"}`))
	noneToken := noneHeader + "." + payload + "."

	_, err := engine.Verify(noneToken)
	if err != ErrAlgorithmMismatch && err != ErrInvalidToken {
		t.Fatalf("expected ErrAlgorithmMismatch on 'none' algorithm header attack, got: %v", err)
	}

	// 2. Mismatched algorithm: token specifies HS512, engine expects HS256
	hs512Engine, _ := NewHMACEngine(HS512, secret)
	hs512Token, _ := hs512Engine.Sign(&Claims{StandardClaims: StandardClaims{Subject: "user-1"}})

	_, err = engine.Verify(hs512Token)
	if err != ErrAlgorithmMismatch {
		t.Fatalf("expected ErrAlgorithmMismatch when algorithm header does not match engine, got: %v", err)
	}
}
