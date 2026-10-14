package download

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
)

// AllowPrivateNetworks is a flag to allow loopback and private IP addresses (mainly for test suites).
var AllowPrivateNetworks = false

// lookupIP resolves hostnames to IPs; overridable in tests to operate offline/in sandboxes.
var lookupIP = net.LookupIP

var privateCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",    // IPv4 loopback
		"10.0.0.0/8",     // RFC 1918 class A
		"172.16.0.0/12",  // RFC 1918 class B
		"192.168.0.0/16", // RFC 1918 class C
		"169.254.0.0/16", // IPv4 Link-local / Cloud metadata (AWS, GCP, Azure)
		"0.0.0.0/8",      // Current network
		"::1/128",        // IPv6 loopback
		"fe80::/10",      // IPv6 link-local
		"fc00::/7",       // IPv6 unique local
	}
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, block)
		}
	}
}

// IsPrivateIP checks if an IP belongs to private, loopback, or cloud metadata networks.
func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	for _, block := range privateCIDRs {
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateSafeURL checks if the target URL is safe and not an SSRF exploit targeting internal networks.
func ValidateSafeURL(rawURL string, allowPrivate bool) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("malformed URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported URL scheme '%s': must be http or https", scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, errors.New("missing host in URL")
	}

	if allowPrivate || AllowPrivateNetworks {
		return u, nil
	}

	if strings.EqualFold(hostname, "localhost") {
		return nil, errors.New("access to localhost is prohibited for security")
	}

	ip := net.ParseIP(hostname)
	if ip != nil {
		if IsPrivateIP(ip) {
			return nil, fmt.Errorf("access to private IP address %s is prohibited", hostname)
		}
	} else {
		ips, err := lookupIP(hostname)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve host %s: %w", hostname, err)
		}
		for _, resolvedIP := range ips {
			if IsPrivateIP(resolvedIP) {
				return nil, fmt.Errorf("host %s resolves to private IP address %s", hostname, resolvedIP.String())
			}
		}
	}

	return u, nil
}
