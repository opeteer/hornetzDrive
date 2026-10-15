package crypto

// DummyVK is deprecated and retained for backwards-compatible test stubs.
// In production, use GetStandardStorageKey() or the session Vault Key.
func DummyVK() []byte {
	return GetStandardStorageKey()
}
