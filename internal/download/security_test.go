package download

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestValidateSafeURL_SSRF(t *testing.T) {
	// Ensure AllowPrivateNetworks is false for security testing
	orig := AllowPrivateNetworks
	AllowPrivateNetworks = false
	defer func() { AllowPrivateNetworks = orig }()

	origLookup := lookupIP
	lookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "releases.ubuntu.com":
			return []net.IP{net.ParseIP("185.125.190.40")}, nil
		case "rebind.internal.test":
			return []net.IP{net.ParseIP("192.168.1.50")}, nil
		default:
			return net.LookupIP(host)
		}
	}
	defer func() { lookupIP = origLookup }()

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
		{"DNS Rebinding to Private IP", "http://rebind.internal.test/secret.txt", true},
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

func TestSafeDialContext_BlocksPrivateNetworks(t *testing.T) {
	orig := AllowPrivateNetworks
	AllowPrivateNetworks = false
	defer func() { AllowPrivateNetworks = orig }()

	origLookup := lookupIP
	lookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "rebind.internal.test":
			return []net.IP{net.ParseIP("192.168.1.50")}, nil
		case "safe.public.test":
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		default:
			return net.LookupIP(host)
		}
	}
	defer func() { lookupIP = origLookup }()

	dialer := SafeDialContext(time.Second, false)
	ctx := context.Background()

	blockedAddrs := []string{
		"127.0.0.1:80",
		"127.0.0.2:8080",
		"localhost:3000",
		"10.0.0.1:443",
		"172.16.5.10:80",
		"192.168.1.1:80",
		"169.254.169.254:80",
		"rebind.internal.test:80",
	}

	for _, addr := range blockedAddrs {
		_, err := dialer(ctx, "tcp", addr)
		if err == nil {
			t.Errorf("Expected SafeDialContext to block %s, but dial succeeded or was allowed", addr)
		}
	}
}

func TestValidatePeerAddress_BlocksPrivatePeers(t *testing.T) {
	orig := AllowPrivateNetworks
	AllowPrivateNetworks = false
	defer func() { AllowPrivateNetworks = orig }()

	origLookup := lookupIP
	lookupIP = func(host string) ([]net.IP, error) {
		if host == "evil.peer.test" {
			return []net.IP{net.ParseIP("10.10.10.10")}, nil
		}
		return net.LookupIP(host)
	}
	defer func() { lookupIP = origLookup }()

	blockedPeers := []string{
		"127.0.0.1:6881",
		"localhost:6881",
		"192.168.1.254:6881",
		"169.254.169.254:80",
		"evil.peer.test:6881",
	}

	for _, peer := range blockedPeers {
		if err := ValidatePeerAddress(peer, false); err == nil {
			t.Errorf("Expected ValidatePeerAddress to reject %s, got nil", peer)
		}
	}

	if err := ValidatePeerAddress("93.184.216.34:6881", false); err != nil {
		t.Errorf("Expected public peer to be allowed, got error: %v", err)
	}
}

func TestNewSafeHTTPClient_BlocksSSRF(t *testing.T) {
	orig := AllowPrivateNetworks
	AllowPrivateNetworks = false
	defer func() { AllowPrivateNetworks = orig }()

	client := NewSafeHTTPClient(2*time.Second, 5, false)

	// Direct attempt to loopback
	_, err := client.Get("http://127.0.0.1:8080/secret")
	if err == nil {
		t.Errorf("Expected NewSafeHTTPClient to block request to 127.0.0.1")
	}

	// Direct attempt to cloud metadata
	_, err = client.Get("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Errorf("Expected NewSafeHTTPClient to block request to AWS metadata endpoint")
	}
}
