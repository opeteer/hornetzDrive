package download

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// DirectFileInfo contains metadata extracted from the HTTP response headers.
type DirectFileInfo struct {
	Filename   string
	MimeType   string
	TotalBytes int64
}

// DirectDownloader handles direct HTTP/HTTPS downloads.
type DirectDownloader struct {
	HTTPClient *http.Client
}

func NewDirectDownloader() *DirectDownloader {
	return &DirectDownloader{
		HTTPClient: &http.Client{
			Timeout: 2 * time.Hour, // Allow large file streaming
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return errors.New("stopped after 10 redirects")
				}
				return nil
			},
		},
	}
}

// ParseFilenameFromHeaders extracts filename from Content-Disposition or URL path.
func ParseFilenameFromHeaders(header string, rawURL string) string {
	if header != "" {
		if _, params, err := mime.ParseMediaType(header); err == nil {
			if filename, ok := params["filename"]; ok && filename != "" {
				return CleanFilename(filename, "")
			}
			if filename, ok := params["filename*"]; ok && filename != "" {
				// Format: UTF-8''encoded_name
				parts := strings.SplitN(filename, "''", 2)
				if len(parts) == 2 {
					if unescaped, err := url.PathUnescape(parts[1]); err == nil {
						return CleanFilename(unescaped, "")
					}
				}
				return CleanFilename(filename, "")
			}
		}
	}

	// Fallback to URL path basename
	if u, err := url.Parse(rawURL); err == nil {
		cleanPath := path.Base(u.Path)
		if unescaped, err := url.PathUnescape(cleanPath); err == nil && unescaped != "" && unescaped != "/" && unescaped != "." {
			return CleanFilename(unescaped, "")
		}
	}

	return fmt.Sprintf("download_%d", time.Now().Unix())
}

// DownloadDirect streams the remote HTTP payload into destWriter while reporting progress.
func (dd *DirectDownloader) DownloadDirect(ctx context.Context, targetURL string, destWriter io.Writer, onProgress func(downloaded int64, total int64, speed string)) (*DirectFileInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid download request: %w", err)
	}
	req.Header.Set("User-Agent", "HornetzDrive/2.0")

	resp, err := dd.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remote server returned HTTP %d %s", resp.StatusCode, resp.Status)
	}

	filename := ParseFilenameFromHeaders(resp.Header.Get("Content-Disposition"), targetURL)
	mimeType := resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	// Strip parameters like charset from mime type
	if mediaType, _, err := mime.ParseMediaType(mimeType); err == nil {
		mimeType = mediaType
	}

	totalBytes := resp.ContentLength

	fileInfo := &DirectFileInfo{
		Filename:   filename,
		MimeType:   mimeType,
		TotalBytes: totalBytes,
	}

	if err := streamWithProgress(ctx, resp.Body, destWriter, totalBytes, onProgress); err != nil {
		return nil, err
	}

	return fileInfo, nil
}
