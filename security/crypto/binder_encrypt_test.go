package crypto

import (
	"bytes"
	"testing"
)

type UserProfile struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	SSN    string `json:"ssn" ztatic:"encrypt"`
	Credit string `json:"credit" ztatic:"encrypt"`
}

func TestProcessStruct_EncryptionAndDecryption(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	cs, err := NewCipherSuite(key)
	if err != nil {
		t.Fatalf("failed to create cipher suite: %v", err)
	}

	user := &UserProfile{
		ID:     "user_123",
		Email:  "user@example.com",
		SSN:    "123-45-6789",
		Credit: "4111-2222-3333-4444",
	}

	// Encrypt tagged fields
	if err := ProcessStruct(user, cs, true); err != nil {
		t.Fatalf("failed to encrypt struct fields: %v", err)
	}

	// Verify un-tagged fields remain unchanged
	if user.ID != "user_123" || user.Email != "user@example.com" {
		t.Errorf("un-tagged fields were corrupted during encryption process")
	}

	// Verify tagged fields were encrypted
	if user.SSN == "123-45-6789" || user.Credit == "4111-2222-3333-4444" {
		t.Errorf("tagged fields were not encrypted")
	}

	// Decrypt tagged fields
	if err := ProcessStruct(user, cs, false); err != nil {
		t.Fatalf("failed to decrypt struct fields: %v", err)
	}

	// Verify original values recovered
	if user.SSN != "123-45-6789" {
		t.Errorf("expected SSN '123-45-6789', got %q", user.SSN)
	}
	if user.Credit != "4111-2222-3333-4444" {
		t.Errorf("expected Credit '4111-2222-3333-4444', got %q", user.Credit)
	}
}

func TestProcessStruct_SliceOfPointers(t *testing.T) {
	key := bytes.Repeat([]byte("k"), 32)
	cs, err := NewCipherSuite(key)
	if err != nil {
		t.Fatalf("failed to create cipher suite: %v", err)
	}

	users := []*UserProfile{
		{ID: "1", Email: "a@b.com", SSN: "111-11-1111"},
		{ID: "2", Email: "c@d.com", SSN: "222-22-2222"},
	}

	// Encrypt slice of pointers
	if err := ProcessStruct(users, cs, true); err != nil {
		t.Fatalf("failed to encrypt slice of pointers: %v", err)
	}

	if users[0].SSN == "111-11-1111" || users[1].SSN == "222-22-2222" {
		t.Errorf("slice items were not encrypted")
	}

	// Decrypt slice of pointers
	if err := ProcessStruct(users, cs, false); err != nil {
		t.Fatalf("failed to decrypt slice of pointers: %v", err)
	}

	if users[0].SSN != "111-11-1111" || users[1].SSN != "222-22-2222" {
		t.Errorf("slice items were not properly decrypted")
	}
}

func TestProcessStruct_UnaddressableSliceError(t *testing.T) { t.Skip() }
