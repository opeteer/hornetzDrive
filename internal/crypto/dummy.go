package crypto

// DummyVK returns a hardcoded 32-byte Vault Key for testing Phase 3
// before the authentication system is implemented.
func DummyVK() []byte {
	return []byte("0123456789abcdef0123456789abcdef")
}
