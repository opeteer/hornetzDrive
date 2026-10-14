package download

import (
	"errors"
	"path/filepath"
	"strings"
)

// IsDownloadLink returns true if the input string looks like a valid download URL or magnet link.
func IsDownloadLink(link string) bool {
	trimmed := strings.TrimSpace(link)
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return len(trimmed) > 8 && !strings.ContainsAny(trimmed, " \t\r\n")
	}
	if strings.HasPrefix(trimmed, "magnet:?") {
		return len(trimmed) > 8 && strings.Contains(trimmed, "xt=urn:btih:")
	}
	return false
}

// DetectLinkType inspects the URI and returns whether it is a direct download or a magnet link.
func DetectLinkType(link string) (DownloadType, error) {
	trimmed := strings.TrimSpace(link)
	if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
		return DownloadTypeDirect, nil
	}
	if strings.HasPrefix(trimmed, "magnet:?") {
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
	return clean
}
