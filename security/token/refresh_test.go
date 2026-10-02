package token

import (
	"context"
	"testing"
	"time"
)

func TestRefreshTokenRotation_AndReuseDetection(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	cfg := DefaultConfig(secret)
	cfg.AccessTTL = 5 * time.Minute
	cfg.RefreshTTL = 1 * time.Hour

	mgr, err := NewManager(cfg)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	// 1. Initial login: generate token pair
	pair1, err := mgr.CreateTokenPair(ctx, &Claims{StandardClaims: StandardClaims{Subject: "user-alpha"}})
	if err != nil {
		t.Fatalf("failed to create token pair: %v", err)
	}

	// 2. Normal rotation: user exchanges pair1.RefreshToken
	pair2, err := mgr.RefreshTokens(ctx, pair1.RefreshToken, nil)
	if err != nil {
		t.Fatalf("failed to refresh token: %v", err)
	}
	if pair2.RefreshToken == pair1.RefreshToken {
		t.Fatalf("refresh token was not rotated")
	}

	// Verify new access token has the correct subject
	tok2, err := mgr.Verify(pair2.AccessToken)
	if err != nil {
		t.Fatalf("new access token verification failed: %v", err)
	}
	if tok2.Claims.Subject != "user-alpha" {
		t.Fatalf("expected subject user-alpha, got: %s", tok2.Claims.Subject)
	}

	// 3. Attack Simulation / Reuse Detection:
	// Attacker (or replayed client) tries to use pair1.RefreshToken again!
	_, err = mgr.RefreshTokens(ctx, pair1.RefreshToken, nil)
	if err != ErrRefreshTokenReused {
		t.Fatalf("expected ErrRefreshTokenReused on re-use of old token, got: %v", err)
	}

	// 4. Verify that the entire family was invalidated:
	// Even pair2.RefreshToken (the legitimate descendant) must now be invalidated!
	_, err = mgr.RefreshTokens(ctx, pair2.RefreshToken, nil)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken because family was revoked, got: %v", err)
	}
}
