package download

import (
	"encoding/base32"
	"encoding/hex"
	"strings"
	"testing"
)

func TestParseMagnetURI_ValidHex(t *testing.T) {
	raw := "magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=archlinux-2026.01.01-x86_64.iso&tr=http%3A%2F%2Ftracker.archlinux.org%3A6969%2Fannounce&tr=udp%3A%2F%2Ftracker.opentrackr.org%3A1337&ws=https%3A%2F%2Fgeo.mirror.pkgbuild.com%2Fiso%2F&xl=1048576"

	info, err := ParseMagnetURI(raw)
	if err != nil {
		t.Fatalf("ParseMagnetURI failed: %v", err)
	}

	if info.HexHash != "da39a3ee5e6b4b0d3255bfef95601890afd80709" {
		t.Errorf("Expected HexHash da39a3ee5e6b4b0d3255bfef95601890afd80709, got %s", info.HexHash)
	}

	expectedHashBytes, _ := hex.DecodeString("da39a3ee5e6b4b0d3255bfef95601890afd80709")
	if string(info.InfoHash[:]) != string(expectedHashBytes) {
		t.Errorf("InfoHash byte mismatch")
	}

	if info.DisplayName != "archlinux-2026.01.01-x86_64.iso" {
		t.Errorf("Expected DisplayName 'archlinux-2026.01.01-x86_64.iso', got %s", info.DisplayName)
	}

	if len(info.Trackers) != 2 {
		t.Errorf("Expected 2 trackers, got %d", len(info.Trackers))
	}

	if len(info.WebSeeds) != 1 || info.WebSeeds[0] != "https://geo.mirror.pkgbuild.com/iso/" {
		t.Errorf("Expected web seed https://geo.mirror.pkgbuild.com/iso/, got %v", info.WebSeeds)
	}

	if info.ExactLength != 1048576 {
		t.Errorf("Expected ExactLength 1048576, got %d", info.ExactLength)
	}
}

func TestParseMagnetURI_Base32(t *testing.T) {
	expectedHex := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	rawBytes, _ := hex.DecodeString(expectedHex)
	b32 := strings.TrimRight(base32.StdEncoding.EncodeToString(rawBytes), "=")
	raw := "magnet:?xt=urn:btih:" + b32 + "&dn=test_base32.dat"

	info, err := ParseMagnetURI(raw)
	if err != nil {
		t.Fatalf("ParseMagnetURI with Base32 failed: %v", err)
	}

	if info.HexHash != expectedHex {
		t.Errorf("Expected HexHash %s, got %s", expectedHex, info.HexHash)
	}

	if info.DisplayName != "test_base32.dat" {
		t.Errorf("Expected DisplayName test_base32.dat, got %s", info.DisplayName)
	}
}

func TestParseMagnetURI_Errors(t *testing.T) {
	invalidLinks := []string{
		"http://not-a-magnet.com",
		"magnet:?",
		"magnet:?dn=testfile.zip",
		"magnet:?xt=urn:other:12345",
		"magnet:?xt=urn:btih:short_hash",
		"magnet:?xt=urn:btih:not_hex_zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
	}

	for _, link := range invalidLinks {
		if _, err := ParseMagnetURI(link); err == nil {
			t.Errorf("Expected error for invalid link %q, but got nil", link)
		}
	}
}
