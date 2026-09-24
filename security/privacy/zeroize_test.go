package privacy

import (
	"testing"
)

func TestZeroize(t *testing.T) {
	data := []byte("SuperSecretPassword")
	Zeroize(data)

	for i, b := range data {
		if b != 0 {
			t.Errorf("byte at index %d was not zeroed out, got %d", i, b)
		}
	}
}
