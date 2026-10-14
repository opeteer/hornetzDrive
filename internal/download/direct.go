package download

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path"
	"strings"
	"time"
)

// DirectFileInfo contains metadata extracted from the HTTP response headers and stream.
type DirectFileInfo struct {
	Filename   string
	MimeType   string
	TotalBytes int64
}

// DirectDownloader handles direct HTTP/HTTPS downloads with domain resolution and smart sniffing.
type DirectDownloader struct {
	HTTPClient *http.Client
}

func NewDirectDownloader() *DirectDownloader {
	jar, _ := cookiejar.New(nil)
	return &DirectDownloader{
		HTTPClient: &http.Client{
			Jar:     jar,
			Timeout: 2 * time.Hour, // Allow large file streaming
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 15 {
					return errors.New("stopped after 15 redirects")
				}
				if _, err := ValidateSafeURL(req.URL.String(), false); err != nil {
					return fmt.Errorf("redirect blocked by security policy: %w", err)
				}
				return nil
			},
		},
	}
}

// ParseFilenameFromHeaders extracts filename from Content-Disposition, query params, or URL path.
func ParseFilenameFromHeaders(header string, rawURL string) string {
	if header != "" {
		if _, params, err := mime.ParseMediaType(header); err == nil {
			if filename, ok := params["filename*"]; ok && filename != "" {
				// Format: UTF-8''encoded_name or ISO-8859-1''encoded_name
				parts := strings.SplitN(filename, "''", 2)
				if len(parts) == 2 {
					if unescaped, err := url.PathUnescape(parts[1]); err == nil {
						return CleanFilename(unescaped, "")
					}
				}
				return CleanFilename(filename, "")
			}
			if filename, ok := params["filename"]; ok && filename != "" {
				return CleanFilename(filename, "")
			}
		}
	}

	// Fallback to URL query parameter heuristics (e.g. S3 presigned response-content-disposition or ?filename=...)
	if u, err := url.Parse(rawURL); err == nil {
		q := u.Query()
		if f := q.Get("filename"); f != "" {
			return CleanFilename(f, "")
		}
		if f := q.Get("file"); f != "" {
			return CleanFilename(f, "")
		}
		if rcd := q.Get("response-content-disposition"); rcd != "" {
			if _, params, err := mime.ParseMediaType(rcd); err == nil {
				if filename, ok := params["filename"]; ok && filename != "" {
					return CleanFilename(filename, "")
				}
			}
		}

		cleanPath := path.Base(u.Path)
		if unescaped, err := url.PathUnescape(cleanPath); err == nil && unescaped != "" && unescaped != "/" && unescaped != "." {
			return CleanFilename(unescaped, "")
		}
	}

	return fmt.Sprintf("download_%d", time.Now().Unix())
}

// DownloadDirect streams the remote HTTP payload into destWriter with domain resolution and magic byte sniffing.
func (dd *DirectDownloader) DownloadDirect(ctx context.Context, targetURL string, destWriter io.Writer, onProgress func(downloaded int64, total int64, speed string)) (*DirectFileInfo, error) {
	resolved, err := ResolveLink(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed resolving download link: %w", err)
	}

	execURL := resolved.ResolvedURL
	if _, err := ValidateSafeURL(execURL, false); err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, execURL, nil)
	if err != nil {
		return nil, fmt.Errorf("invalid download request: %w", err)
	}
	req.Header.Set("User-Agent", DefaultBrowserUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,application/octet-stream,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9,id;q=0.8")
	if resolved.Referer != "" {
		req.Header.Set("Referer", resolved.Referer)
	}
	if resolved.AuthHeader != "" {
		req.Header.Set("Authorization", resolved.AuthHeader)
	}

	resp, err := dd.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download connection failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("remote server returned HTTP %d %s", resp.StatusCode, resp.Status)
	}

	finalURL := resp.Request.URL.String()
	filename := ParseFilenameFromHeaders(resp.Header.Get("Content-Disposition"), finalURL)
	if filename == "" || strings.HasPrefix(filename, "download_") {
		if resolved.Filename != "" && !strings.HasPrefix(resolved.Filename, "download_") {
			filename = resolved.Filename
		}
	}

	mimeType := resp.Header.Get("Content-Type")
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}
	if mediaType, _, err := mime.ParseMediaType(mimeType); err == nil {
		mimeType = mediaType
	}

	totalBytes := resp.ContentLength

	// Magic byte sniffing on first 512 bytes
	peekBuf := make([]byte, 512)
	peekN, readErr := io.ReadFull(resp.Body, peekBuf)
	if readErr != nil && readErr != io.ErrUnexpectedEOF && readErr != io.EOF {
		return nil, fmt.Errorf("failed reading initial response payload: %w", readErr)
	}

	var streamSrc io.Reader
	if peekN > 0 {
		filename, mimeType = SniffMagicBytes(peekBuf[:peekN], filename, mimeType)

		// Guard against HTML interstitials when expecting a binary, archive, or media file
		isHTML := strings.HasPrefix(mimeType, "text/html") || IsHTMLPayload(peekBuf[:peekN])
		isTargetBinary := IsBinaryExtension(filename) || (resolved.Filename != "" && IsBinaryExtension(resolved.Filename))

		if isHTML && isTargetBinary {
			// Read up to 1MB of the HTML body to inspect for recovery links (e.g. MediaFire or Google Drive)
			restOfHTML, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
			fullHTML := string(append(peekBuf[:peekN], restOfHTML...))

			var recoveredURL string
			// 1. MediaFire / Generic download button check
			recoveredURL, _ = ExtractMediaFireDirectLinkFromHTML(fullHTML)

			// 2. Google Drive confirm link check
			if recoveredURL == "" {
				recoveredURL = ExtractGoogleDriveConfirmLinkFromHTML(fullHTML)
			}

			if recoveredURL != "" && recoveredURL != execURL {
				// Retry with the recovered direct download link
				return dd.DownloadDirect(ctx, recoveredURL, destWriter, onProgress)
			}

			return nil, fmt.Errorf("unduhan dibatalkan: tautan mengembalikan halaman web HTML (%s, %d bytes) alih-alih berkas biner %s. Tautan mungkin kedaluwarsa atau memerlukan otentikasi peramban", mimeType, int64(peekN)+int64(len(restOfHTML)), filename)
		}

		streamSrc = io.MultiReader(bytes.NewReader(peekBuf[:peekN]), resp.Body)
	} else {
		streamSrc = resp.Body
	}

	fileInfo := &DirectFileInfo{
		Filename:   filename,
		MimeType:   mimeType,
		TotalBytes: totalBytes,
	}

	if err := streamWithProgress(ctx, streamSrc, destWriter, totalBytes, onProgress); err != nil {
		return nil, err
	}

	return fileInfo, nil
}
