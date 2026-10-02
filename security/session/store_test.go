package session

import (
	"context"
	"testing"
	"time"

	"ztatic-go-framework/security/crypto"
)

func TestMemoryStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStoreWithInterval(0) // disable sweeper for deterministic test
	defer store.Close()

	sess := NewSession(100 * time.Millisecond)
	sess.Set("tier", "enterprise")

	// 1. Save
	if err := store.Save(ctx, sess, 100*time.Millisecond); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	// 2. Get
	loaded, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}
	if loaded.GetString("tier") != "enterprise" {
		t.Fatalf("expected enterprise, got: %s", loaded.GetString("tier"))
	}

	// 3. Touch
	if err := store.Touch(ctx, sess.ID, 200*time.Millisecond); err != nil {
		t.Fatalf("touch failed: %v", err)
	}

	// 4. Destroy
	if err := store.Destroy(ctx, sess.ID); err != nil {
		t.Fatalf("destroy failed: %v", err)
	}
	_, err = store.Get(ctx, sess.ID)
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound after destroy, got: %v", err)
	}
}

func TestMemoryStore_Expiration(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStoreWithInterval(0)
	defer store.Close()

	sess := NewSession(10 * time.Millisecond)
	sess.Set("data", "temp")
	_ = store.Save(ctx, sess, 10*time.Millisecond)

	time.Sleep(20 * time.Millisecond)

	_, err := store.Get(ctx, sess.ID)
	if err != ErrSessionExpired {
		t.Fatalf("expected ErrSessionExpired, got: %v", err)
	}
}

func TestCookieStore_Lifecycle(t *testing.T) {
	ctx := context.Background()
	key := []byte("01234567890123456789012345678901") // 32 bytes
	cs, err := crypto.NewCipherSuite(key)
	if err != nil {
		t.Fatal(err)
	}

	store, err := NewCookieStore(cs)
	if err != nil {
		t.Fatal(err)
	}

	sess := NewSession(1 * time.Hour)
	sess.Set("user_id", "42")
	sess.Flash("msg", "welcome")

	// Save generates encrypted cookie value and puts it in sess.ID
	if err := store.Save(ctx, sess, 1*time.Hour); err != nil {
		t.Fatalf("save failed: %v", err)
	}
	encryptedCookie := sess.ID

	// Load by decrypting the cookie string
	loaded, err := store.Get(ctx, encryptedCookie)
	if err != nil {
		t.Fatalf("get failed: %v", err)
	}

	if loaded.GetString("user_id") != "42" {
		t.Fatalf("expected user_id 42, got: %s", loaded.GetString("user_id"))
	}
	flashes := loaded.Flashes("msg")
	if len(flashes) != 1 || flashes[0] != "welcome" {
		t.Fatalf("unexpected flash content: %v", flashes)
	}

	// Tampered cookie check
	tampered := encryptedCookie[:len(encryptedCookie)-5] + "XXXXX"
	_, err = store.Get(ctx, tampered)
	if err != ErrSessionNotFound {
		t.Fatalf("expected ErrSessionNotFound on tampered cookie, got: %v", err)
	}
}
