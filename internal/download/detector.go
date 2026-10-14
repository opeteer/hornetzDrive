package download

import (
	"errors"
	"path/filepath"
	"strings"
)

// IsDownloadLink returns true if the input string looks like a valid download URL, domain address, or magnet link.
func IsDownloadLink(link string) bool {
	trimmed := strings.TrimSpace(link)
	if trimmed == "" {
		return false
	}

	norm := NormalizeLink(trimmed)
	lower := strings.ToLower(norm)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return len(norm) > 8 && !strings.ContainsAny(norm, " \t\r\n")
	}
	if strings.HasPrefix(lower, "magnet:?") {
		return len(norm) > 8 && strings.Contains(lower, "xt=urn:btih:")
	}
	return false
}

// DetectLinkType inspects the URI and returns whether it is a direct download or a magnet link.
func DetectLinkType(link string) (DownloadType, error) {
	trimmed := strings.TrimSpace(link)
	if trimmed == "" {
		return "", errors.New("empty download link")
	}

	norm := NormalizeLink(trimmed)
	lower := strings.ToLower(norm)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		return DownloadTypeDirect, nil
	}
	if strings.HasPrefix(lower, "magnet:?") {
		return DownloadTypeMagnet, nil
	}
	return "", errors.New("unsupported download link protocol: must start with http://, https://, or magnet:?")
}

// CleanFilename sanitizes a proposed filename for safe filesystem and database storage.
func CleanFilename(name string, fallback string) string {
	clean := filepath.Base(filepath.Clean(strings.TrimSpace(name)))
	if clean == "" || clean == "." || clean == "/" || clean == "\\" || clean == ".." {
		if fallback != "" {
			return fallback
		}
		return "downloaded_file"
	}

	clean = strings.ReplaceAll(clean, `"`, `_`)
	clean = strings.ReplaceAll(clean, `'`, `_`)
	clean = strings.ReplaceAll(clean, `/`, `_`)
	clean = strings.ReplaceAll(clean, `\`, `_`)
	clean = strings.ReplaceAll(clean, "\r", "")
	clean = strings.ReplaceAll(clean, "\n", "")

	trimmed := strings.Trim(clean, "._ ")
	if trimmed == "" {
		if fallback != "" {
			return fallback
		}
		return "downloaded_file"
	}
	return trimmed
}
