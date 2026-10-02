package upload

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"
)

var (
	// invalidFilenameChars matches any character not in [a-zA-Z0-9._-]
	invalidFilenameChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

	// multipleUnderscores matches consecutive underscores
	multipleUnderscores = regexp.MustCompile(`_+`)

	// windowsReservedNames matches DOS/Windows device names that cause issues on FAT/NTFS
	windowsReservedNames = regexp.MustCompile(`^(?i)(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$`)
)

// SanitizeFilename strips directory traversal, control characters, null bytes,
// and unsafe shell symbols from an untrusted client filename.
func SanitizeFilename(filename string) string {
	if filename == "" {
		return "unnamed_file"
	}

	// 1. Remove null bytes immediately
	filename = strings.ReplaceAll(filename, "\x00", "")

	// 2. Strip directory path components (both UNIX / and Windows \)
	filename = strings.ReplaceAll(filename, "\\", "/")
	filename = filepath.Base(filename)
	filename = strings.TrimLeft(filename, `/\.`)

	// 3. Normalize whitespace to underscores
	filename = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return '_'
		}
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, filename)

	// 4. Extract and clean extension
	ext := filepath.Ext(filename)
	base := strings.TrimSuffix(filename, ext)

	// Strip illegal characters from base and extension
	cleanBase := invalidFilenameChars.ReplaceAllString(base, "_")
	cleanBase = multipleUnderscores.ReplaceAllString(cleanBase, "_")
	cleanBase = strings.Trim(cleanBase, "._-")

	cleanExt := strings.ToLower(invalidFilenameChars.ReplaceAllString(ext, ""))
	cleanExt = strings.Trim(cleanExt, ". ")

	// Ensure extension starts with dot if not empty
	if cleanExt != "" {
		cleanExt = "." + cleanExt
	}

	if cleanBase == "" {
		cleanBase = "upload"
	}

	// Prevent Windows reserved device names
	if windowsReservedNames.MatchString(cleanBase) {
		cleanBase = "safe_" + cleanBase
	}

	// Truncate length if excessively long (max 100 chars base)
	if len(cleanBase) > 100 {
		cleanBase = cleanBase[:100]
	}

	result := cleanBase + cleanExt
	if result == "" || result == "." {
		return "upload"
	}

	return result
}

// GenerateStorageKey creates a unique, collision-resistant storage key based on the chosen strategy.
func GenerateStorageKey(strategy NamingStrategy, originalFilename string, content []byte, customFn func(string, []byte) string) string {
	if customFn != nil {
		return customFn(originalFilename, content)
	}

	ext := strings.ToLower(filepath.Ext(SanitizeFilename(originalFilename)))

	switch strategy {
	case StrategySHA256:
		if len(content) > 0 {
			h := sha256.Sum256(content)
			return hex.EncodeToString(h[:]) + ext
		}
		// If content is not in memory, fallback to random UUID-like hash
		return randomHex(32) + ext

	case StrategyULID:
		// Timestamp prefix (ms) + 16 random hex chars
		ts := time.Now().UTC().UnixMilli()
		return fmt.Sprintf("%013x_%s%s", ts, randomHex(8), ext)

	case StrategyOriginalSanitized:
		sanitized := SanitizeFilename(originalFilename)
		sBase := strings.TrimSuffix(sanitized, ext)
		if len(sBase) > 40 {
			sBase = sBase[:40]
		}
		return fmt.Sprintf("%s_%s%s", sBase, randomHex(6), ext)

	case StrategyUUID:
		fallthrough
	default:
		// RFC 4122 v4 UUID format
		return randomUUID() + ext
	}
}

// randomHex returns n random bytes encoded as hex string.
func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// randomUUID generates a cryptographically random RFC 4122 version 4 UUID.
func randomUUID() string {
	var uuid [16]byte
	_, _ = rand.Read(uuid[:])

	// Set version 4 (bits 4-7 of 7th byte = 0100)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set variant 1 (bits 6-7 of 9th byte = 10)
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])
}
