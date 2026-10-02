package session

import (
	"testing"
	"time"
)

func TestSession_GettersSettersAndFlashes(t *testing.T) {
	s := NewSession(30 * time.Minute)

	if len(s.ID) < 32 {
		t.Fatalf("expected high-entropy session ID, got length: %d", len(s.ID))
	}
	if !s.IsNew() {
		t.Errorf("new session should have isNew = true")
	}

	// 1. Primitive Type-Safe Getters/Setters
	s.Set("username", "alice")
	s.Set("age", 30)
	s.Set("is_active", true)

	if s.GetString("username") != "alice" {
		t.Errorf("expected string alice")
	}
	if s.GetInt("age") != 30 {
		t.Errorf("expected int 30")
	}
	if !s.GetBool("is_active") {
		t.Errorf("expected bool true")
	}
	if !s.IsModified() {
		t.Errorf("expected isModified = true after Set")
	}

	// 2. Delete and Clear
	s.Delete("age")
	if s.GetInt("age") != 0 {
		t.Errorf("expected 0 for deleted key")
	}

	s.Clear()
	if s.GetString("username") != "" {
		t.Errorf("expected empty string after Clear")
	}

	// 3. Flash Messages
	s.Flash("notice", "Profile updated")
	s.Flash("notice", "Check your email")

	flashes := s.Flashes("notice")
	if len(flashes) != 2 || flashes[0] != "Profile updated" || flashes[1] != "Check your email" {
		t.Fatalf("unexpected flashes: %v", flashes)
	}

	// Immediate consumption check: subsequent call should be empty
	emptyFlashes := s.Flashes("notice")
	if len(emptyFlashes) != 0 {
		t.Fatalf("flashes should be consumed after first read")
	}
}

func TestSession_RegenerateID_FixationProtection(t *testing.T) {
	s := NewSession(30 * time.Minute)
	originalID := s.ID

	s.Set("role", "admin")

	err := s.RegenerateID()
	if err != nil {
		t.Fatalf("RegenerateID failed: %v", err)
	}

	if s.ID == originalID {
		t.Fatalf("session ID was not updated after RegenerateID")
	}
	if s.OldID() != originalID {
		t.Fatalf("expected OldID to be %s, got: %s", originalID, s.OldID())
	}
	if s.GetString("role") != "admin" {
		t.Fatalf("values lost during RegenerateID")
	}
	if !s.IsNew() || !s.IsModified() {
		t.Fatalf("session should be marked new and modified after RegenerateID")
	}
}

func TestSession_Destroy(t *testing.T) {
	s := NewSession(30 * time.Minute)
	s.Destroy()
	if !s.IsDestroyed() {
		t.Errorf("expected isDestroyed = true")
	}
}
