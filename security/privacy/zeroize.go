package privacy

// Zeroize securely overwrites a byte slice with zeros.
// This is used to remove sensitive cryptographic keys, passwords,
// or PII from heap memory immediately after processing, reducing
// the risk of exposure from memory dumps or panics.
func Zeroize(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}
