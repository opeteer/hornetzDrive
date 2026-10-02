package token

import (
	"testing"
	"time"
)

func TestClaims_Valid(t *testing.T) {
	now := time.Now().Unix()

	// 1. Valid token
	valid := &Claims{
		StandardClaims: StandardClaims{
			ExpiresAt: now + 3600,
			NotBefore: now - 10,
			IssuedAt:  now - 20,
		},
	}
	if err := valid.Valid(0); err != nil {
		t.Fatalf("expected claims to be valid, got: %v", err)
	}

	// 2. Expired token
	expired := &Claims{
		StandardClaims: StandardClaims{
			ExpiresAt: now - 10,
		},
	}
	if err := expired.Valid(0); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired, got: %v", err)
	}

	// 3. Expired within clock skew
	if err := expired.Valid(15 * time.Second); err != nil {
		t.Fatalf("expected token to pass within clock skew, got: %v", err)
	}

	// 4. Not before in future
	future := &Claims{
		StandardClaims: StandardClaims{
			NotBefore: now + 60,
		},
	}
	if err := future.Valid(0); err != ErrTokenNotValidYet {
		t.Fatalf("expected ErrTokenNotValidYet, got: %v", err)
	}
}

func TestClaims_RolesAndScopes(t *testing.T) {
	c := &Claims{
		Roles:    []string{"admin", "editor"},
		Scopes:   []string{"read:users", "write:users"},
		TenantID: "tenant-123",
	}

	if !c.HasRole("admin") || !c.HasRole("ADMIN") {
		t.Errorf("expected case-insensitive HasRole to match")
	}
	if c.HasRole("superadmin") {
		t.Errorf("expected HasRole to fail for missing role")
	}
	if !c.HasAnyRole("viewer", "editor") {
		t.Errorf("expected HasAnyRole to match editor")
	}
	if !c.HasScope("read:users") {
		t.Errorf("expected HasScope to match")
	}
	if !c.HasAllScopes("read:users", "write:users") {
		t.Errorf("expected HasAllScopes to match all")
	}
	if c.HasAllScopes("read:users", "delete:users") {
		t.Errorf("expected HasAllScopes to fail when missing scope")
	}
	if !c.InTenant("tenant-123") {
		t.Errorf("expected InTenant to match")
	}

	actor := c.ToAuditActor("127.0.0.1")
	if actor.Role != "admin" || actor.TenantID != "tenant-123" || actor.IP != "127.0.0.1" {
		t.Errorf("unexpected audit actor: %+v", actor)
	}
}
