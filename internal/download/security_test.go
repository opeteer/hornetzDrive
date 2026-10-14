package download

import (
	"testing"
)

func TestValidateSafeURL_SSRF(t *testing.T) {
	// Ensure AllowPrivateNetworks is false for security testing
	orig := AllowPrivateNetworks
	AllowPrivateNetworks = false
	defer func() { AllowPrivateNetworks = orig }()

	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"IPv4 Loopback", "http://127.0.0.1/secret", true},
		{"IPv4 Loopback 127.0.0.2", "http://127.0.0.2:8080/data", true},
		{"Localhost hostname", "http://localhost:3000/api", true},
		{"Class A Private 10.x", "http://10.0.1.5/file.bin", true},
		{"Class B Private 172.16.x", "http://172.16.0.1/admin", true},
		{"Class C Private 192.168.x", "http://192.168.1.1/backup.tar", true},
		{"AWS Metadata endpoint", "http://169.254.169.254/latest/meta-data/", true},
		{"Public domain", "https://releases.ubuntu.com/24.04/ubuntu.iso", false},
		{"Public IP", "http://93.184.216.34/index.html", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateSafeURL(tc.url, false)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSafeURL(%q) err = %v, wantErr = %v", tc.url, err, tc.wantErr)
			}
		})
	}
}
