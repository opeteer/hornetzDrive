package download

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
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

// ValidatePeerAddress checks if a BitTorrent peer address is valid and not pointing to a private or loopback IP.
func ValidatePeerAddress(peerAddr string, allowPrivate bool) error {
	if allowPrivate || AllowPrivateNetworks {
		return nil
	}
	host, _, err := net.SplitHostPort(peerAddr)
	if err != nil {
		host = peerAddr
	}
	if strings.EqualFold(host, "localhost") {
		return errors.New("peer connection to localhost is prohibited for security")
	}
	ip := net.ParseIP(host)
	if ip != nil {
		if IsPrivateIP(ip) {
			return fmt.Errorf("peer IP %s belongs to a private network", host)
		}
		return nil
	}
	ips, err := lookupIP(host)
	if err != nil {
		return fmt.Errorf("failed to resolve peer host %s: %w", host, err)
	}
	for _, resolvedIP := range ips {
		if IsPrivateIP(resolvedIP) {
			return fmt.Errorf("peer host %s resolves to private IP %s", host, resolvedIP.String())
		}
	}
	return nil
}

// SafeDialContext returns a dialing function that validates IP addresses against SSRF and DNS rebinding attacks.
func SafeDialContext(dialTimeout time.Duration, allowPrivate bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if dialTimeout <= 0 {
		dialTimeout = 10 * time.Second
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address format %s: %w", addr, err)
		}

		if allowPrivate || AllowPrivateNetworks {
			d := net.Dialer{Timeout: dialTimeout}
			return d.DialContext(ctx, network, addr)
		}

		if strings.EqualFold(host, "localhost") {
			return nil, errors.New("access to localhost is prohibited for security")
		}

		var targetIP net.IP
		ip := net.ParseIP(host)
		if ip != nil {
			if IsPrivateIP(ip) {
				return nil, fmt.Errorf("access to private IP address %s is prohibited", host)
			}
			targetIP = ip
		} else {
			ips, err := lookupIP(host)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve host %s: %w", host, err)
			}
			for _, resolvedIP := range ips {
				if IsPrivateIP(resolvedIP) {
					return nil, fmt.Errorf("host %s resolves to private IP %s", host, resolvedIP.String())
				}
				if targetIP == nil {
					targetIP = resolvedIP
				}
			}
		}

		if targetIP == nil {
			return nil, fmt.Errorf("no valid IP address found for %s", host)
		}

		// Connect directly to the verified safe IP to prevent DNS rebinding races
		safeAddr := net.JoinHostPort(targetIP.String(), port)
		d := net.Dialer{Timeout: dialTimeout}
		return d.DialContext(ctx, network, safeAddr)
	}
}

// NewSafeTransport returns an http.Transport configured with SSRF-safe connection dialing.
func NewSafeTransport(dialTimeout time.Duration, allowPrivate bool) *http.Transport {
	return &http.Transport{
		DialContext:           SafeDialContext(dialTimeout, allowPrivate),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
	}
}

// NewSafeHTTPClient returns an http.Client with safe dialer and strict redirect validation.
func NewSafeHTTPClient(timeout time.Duration, maxRedirects int, allowPrivate bool) *http.Client {
	if maxRedirects <= 0 {
		maxRedirects = 10
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: NewSafeTransport(10*time.Second, allowPrivate),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= maxRedirects {
				return fmt.Errorf("stopped after %d redirects", maxRedirects)
			}
			if _, err := ValidateSafeURL(req.URL.String(), allowPrivate); err != nil {
				return fmt.Errorf("redirect blocked by security policy: %w", err)
			}
			return nil
		},
	}
}

