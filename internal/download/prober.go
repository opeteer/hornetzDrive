package download

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ProbeResult holds metadata discovered via preflight HTTP probing.
type ProbeResult struct {
	URL           string       `json:"url"`
	ResolvedURL   string       `json:"resolved_url"`
	FinalURL      string       `json:"final_url"`
	Type          DownloadType `json:"type"`
	Provider      string       `json:"provider"`
	ProviderIcon  string       `json:"provider_icon"`
	Filename      string       `json:"name"`
	FileSize      int64        `json:"file_size"`
	FormattedSize string       `json:"formatted_size"`
	MimeType      string       `json:"mime_type"`
	Category      string       `json:"category"`
	Resumable     bool         `json:"resumable"`
	StatusCode    int          `json:"status_code"`
	IsTorrent     bool         `json:"is_torrent"`
	IsBatch       bool         `json:"is_batch"`
	BatchCount    int          `json:"batch_count"`
	BatchItems    []string     `json:"batch_items,omitempty"`
}

// FormatFileSize returns a human-readable file size string.
func FormatFileSize(bytes int64) string {
	if bytes <= 0 {
		return "-"
	}
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	units := []string{"KB", "MB", "GB", "TB", "PB"}
	return fmt.Sprintf("%.2f %s", float64(bytes)/float64(div), units[exp])
}

// ClassifyCategory maps MIME type or file extension to a logical category.
func ClassifyCategory(filename string, mimeType string) string {
	ext := strings.ToLower(filepath.Ext(filename))
	m := strings.ToLower(mimeType)

	switch {
	case strings.HasPrefix(m, "image/"):
		return "image"
	case strings.HasPrefix(m, "video/"):
		return "video"
	case strings.HasPrefix(m, "audio/"):
		return "audio"
	case ext == ".pdf" || strings.Contains(m, "pdf") || strings.Contains(m, "word") || strings.Contains(m, "document") || strings.Contains(m, "presentation") || strings.Contains(m, "spreadsheet"):
		return "document"
	case ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".tar" || ext == ".gz" || ext == ".bz2" || ext == ".xz" || strings.Contains(m, "zip") || strings.Contains(m, "compressed") || strings.Contains(m, "tar") || strings.Contains(m, "archive"):
		return "archive"
	case ext == ".iso" || ext == ".dmg" || ext == ".img":
		return "disk_image"
	case ext == ".exe" || ext == ".msi" || ext == ".bin" || ext == ".apk" || ext == ".deb" || ext == ".rpm" || ext == ".elf" || strings.Contains(m, "executable"):
		return "executable"
	case ext == ".go" || ext == ".py" || ext == ".js" || ext == ".ts" || ext == ".html" || ext == ".css" || ext == ".json" || ext == ".yaml" || ext == ".yml" || ext == ".sql" || ext == ".sh":
		return "code"
	default:
		return "file"
	}
}

// ProbeLink performs deep preflight inspection on a download link.
func ProbeLink(ctx context.Context, client *http.Client, rawURL string) (*ProbeResult, error) {
	// First check if batch
	if batch, err := ExpandBatchLinks(rawURL); err == nil && len(batch) > 1 {
		firstResolved, _ := ResolveLink(batch[0])
		provider := "Batch Downloads"
		providerIcon := "layers"
		if firstResolved != nil {
			provider = fmt.Sprintf("Batch (%s)", firstResolved.Provider)
		}
		return &ProbeResult{
			URL:           rawURL,
			ResolvedURL:   batch[0],
			FinalURL:      batch[0],
			Type:          DownloadTypeDirect,
			Provider:      provider,
			ProviderIcon:  providerIcon,
			Filename:      fmt.Sprintf("Batch_%d_items", len(batch)),
			FileSize:      0,
			FormattedSize: fmt.Sprintf("%d berkas", len(batch)),
			Category:      "archive",
			IsBatch:       true,
			BatchCount:    len(batch),
			BatchItems:    batch,
		}, nil
	}

	resolved, err := ResolveLink(rawURL)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve link: %w", err)
	}

	if resolved.Type == DownloadTypeMagnet {
		return &ProbeResult{
			URL:           rawURL,
			ResolvedURL:   resolved.ResolvedURL,
			FinalURL:      resolved.ResolvedURL,
			Type:          DownloadTypeMagnet,
			Provider:      resolved.Provider,
			ProviderIcon:  resolved.ProviderIcon,
			Filename:      resolved.Filename,
			FileSize:      0,
			FormattedSize: "P2P Swarm",
			Category:      "archive",
			Resumable:     true,
			StatusCode:    200,
			IsTorrent:     true,
		}, nil
	}

	if client == nil {
		client = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 15 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}

	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// 1. Try HEAD request first
	req, err := http.NewRequestWithContext(probeCtx, http.MethodHead, resolved.ResolvedURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid probe request: %w", err)
	}
	req.Header.Set("User-Agent", DefaultBrowserUserAgent)
	req.Header.Set("Accept", "*/*")
	if resolved.Referer != "" {
		req.Header.Set("Referer", resolved.Referer)
	}
	if resolved.AuthHeader != "" {
		req.Header.Set("Authorization", resolved.AuthHeader)
	}

	resp, err := client.Do(req)

	// If HEAD failed or gave 405 Method Not Allowed / 403 Forbidden, fallback to GET with Range: bytes=0-0
	if err != nil || (resp != nil && (resp.StatusCode == http.StatusMethodNotAllowed || resp.StatusCode == http.StatusForbidden || resp.StatusCode >= 400)) {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}

		getReq, getErr := http.NewRequestWithContext(probeCtx, http.MethodGet, resolved.ResolvedURL, nil)
		if getErr == nil {
			getReq.Header.Set("User-Agent", DefaultBrowserUserAgent)
			getReq.Header.Set("Accept", "*/*")
			if resolved.Referer != "" {
				getReq.Header.Set("Referer", resolved.Referer)
			}
			getReq.Header.Set("Range", "bytes=0-0")
			if resolved.AuthHeader != "" {
				getReq.Header.Set("Authorization", resolved.AuthHeader)
			}
			resp, err = client.Do(getReq)
		}
	}

	if err != nil {
		return nil, fmt.Errorf("probe connection failed: %w", err)
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()
	statusCode := resp.StatusCode

	// Parse filename
	filename := ParseFilenameFromHeaders(resp.Header.Get("Content-Disposition"), finalURL)
	if filename == "" || strings.HasPrefix(filename, "download_") {
		if resolved.Filename != "" && !strings.HasPrefix(resolved.Filename, "download_") {
			filename = resolved.Filename
		}
	}

	// Parse MIME type
	mimeType := resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	if parsedMediaType, _, err := mime.ParseMediaType(mimeType); err == nil {
		mimeType = parsedMediaType
	}

	// Extract Content-Length or Content-Range
	var totalBytes int64 = resp.ContentLength
	if contentRange := resp.Header.Get("Content-Range"); contentRange != "" {
		// e.g. bytes 0-0/1048576
		parts := strings.Split(contentRange, "/")
		if len(parts) == 2 && parts[1] != "*" {
			if parsedTotal, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
				totalBytes = parsedTotal
			}
		}
	}

	// Resumability check
	acceptRanges := resp.Header.Get("Accept-Ranges")
	resumable := strings.EqualFold(acceptRanges, "bytes") || resp.StatusCode == http.StatusPartialContent

	// Dynamic category
	category := ClassifyCategory(filename, mimeType)

	return &ProbeResult{
		URL:           rawURL,
		ResolvedURL:   resolved.ResolvedURL,
		FinalURL:      finalURL,
		Type:          DownloadTypeDirect,
		Provider:      resolved.Provider,
		ProviderIcon:  resolved.ProviderIcon,
		Filename:      filename,
		FileSize:      totalBytes,
		FormattedSize: FormatFileSize(totalBytes),
		MimeType:      mimeType,
		Category:      category,
		Resumable:     resumable,
		StatusCode:    statusCode,
		IsTorrent:     resolved.IsTorrent,
	}, nil
}
