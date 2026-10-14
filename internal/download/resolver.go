package download

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// DefaultBrowserUserAgent is a standard, modern browser signature to avoid automated bot/hotlink blocking.
const DefaultBrowserUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"

var (
	markdownLinkRegex    = regexp.MustCompile(`^\[.*?\]\((https?://[^\s)]+)\)$`)
	angleBracketRegex    = regexp.MustCompile(`^<(https?://[^>]+)>$`)
	domainPrefixRegex    = regexp.MustCompile(`^([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(:\d+)?(/.*)?$`)
	gdriveFileIDRegex    = regexp.MustCompile(`/file/d/([a-zA-Z0-9_-]+)`)
	gdriveConfirmRegex   = regexp.MustCompile(`(?i)href\s*=\s*["'](/uc\?export=download[^"']+)["']`)
	gdriveConfirmUrlRegex = regexp.MustCompile(`(?i)href\s*=\s*["'](https?://drive\.google\.com/uc\?export=download[^"']+)["']`)
	githubBlobRegex      = regexp.MustCompile(`^/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$`)
	gitlabBlobRegex      = regexp.MustCompile(`^/([^/]+)/([^/]+)/-/blob/([^/]+)/(.*)$`)
	bitbucketSrcRegex    = regexp.MustCompile(`^/([^/]+)/([^/]+)/src/([^/]+)/(.*)$`)
	huggingfaceRegex     = regexp.MustCompile(`^/([^/]+)/([^/]+)/blob/([^/]+)/(.*)$`)
	mediafireBtnRegex    = regexp.MustCompile(`(?i)href\s*=\s*["'](https?://download\d*\.mediafire\.com/[^"']+)["']`)
	mediafireRawCdnRegex = regexp.MustCompile(`https?://download\d*\.mediafire\.com/[a-zA-Z0-9_\-\./%]+`)
	mediafireTitleRegex  = regexp.MustCompile(`(?i)<title>(?:Download\s*)?([^<]+?)(?:\s*-\s*MediaFire)?</title>`)
)

// ResolvedLink represents a normalized and domain-resolved download target.
type ResolvedLink struct {
	OriginalURL  string       `json:"original_url"`
	ResolvedURL  string       `json:"resolved_url"`
	Domain       string       `json:"domain"`
	Provider     string       `json:"provider"`
	ProviderIcon string       `json:"provider_icon"`
	Filename     string       `json:"filename,omitempty"`
	AuthHeader   string       `json:"-"`
	Referer      string       `json:"-"`
	Type         DownloadType `json:"type"`
	IsTorrent    bool         `json:"is_torrent"`
}

// NormalizeLink cleans and normalizes user input into a valid URL or magnet URI.
func NormalizeLink(input string) string {
	s := strings.TrimSpace(input)
	if s == "" {
		return ""
	}

	// Strip surrounding double or single quotes
	if (strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`)) ||
		(strings.HasPrefix(s, `'`) && strings.HasSuffix(s, `'`)) {
		s = strings.Trim(s, `"'`)
		s = strings.TrimSpace(s)
	}

	// Markdown link syntax: [label](https://...)
	if match := markdownLinkRegex.FindStringSubmatch(s); len(match) == 2 {
		s = match[1]
	}

	// Angle bracket syntax: <https://...>
	if match := angleBracketRegex.FindStringSubmatch(s); len(match) == 2 {
		s = match[1]
	}

	// Magnet links are preserved directly
	if strings.HasPrefix(s, "magnet:?") {
		return s
	}

	// Scheme-less URLs (e.g. "drive.google.com/...", "releases.ubuntu.com/...", "github.com/...")
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") && !strings.HasPrefix(s, "ftp://") {
		lower := strings.ToLower(s)
		isDomainWithSlash := strings.Contains(s, "/") && domainPrefixRegex.MatchString(s)
		isWww := strings.HasPrefix(lower, "www.") && domainPrefixRegex.MatchString(s)
		if isDomainWithSlash || isWww {
			s = "https://" + s
		}
	}

	// Unwrap common redirect wrappers
	s = unwrapRedirects(s)

	return s
}

// unwrapRedirects extracts target URLs from search or click tracking redirects.
func unwrapRedirects(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	host := strings.ToLower(u.Host)

	// Google click redirect: google.com/url?q=...
	if strings.Contains(host, "google.") && u.Path == "/url" {
		if target := u.Query().Get("q"); target != "" {
			return target
		}
		if target := u.Query().Get("url"); target != "" {
			return target
		}
	}

	// Generic anonymizer / wrapper: href.li/?... or gate.sc/?url=...
	if strings.Contains(host, "href.li") {
		trimmed := strings.TrimPrefix(u.RequestURI(), "/?")
		if strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") {
			return trimmed
		}
	}

	return rawURL
}

// ExtractBasicAuth removes user credentials from a URL and formats the Basic Auth header.
func ExtractBasicAuth(rawURL string) (string, string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, "", err
	}

	if u.User == nil {
		return rawURL, "", nil
	}

	username := u.User.Username()
	password, _ := u.User.Password()
	authHeader := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))

	u.User = nil
	return u.String(), authHeader, nil
}

// ResolveLink runs domain-specific analyzers and transforms the link into a direct download target.
func ResolveLink(rawInput string) (*ResolvedLink, error) {
	norm := NormalizeLink(rawInput)
	if norm == "" {
		return nil, fmt.Errorf("empty download link")
	}

	if strings.HasPrefix(norm, "magnet:?") {
		magInfo, err := ParseMagnetURI(norm)
		filename := "torrent_download.bin"
		if err == nil && magInfo.DisplayName != "" {
			filename = magInfo.DisplayName
		}
		return &ResolvedLink{
			OriginalURL:  rawInput,
			ResolvedURL:  norm,
			Domain:       "BitTorrent",
			Provider:     "BitTorrent Swarm",
			ProviderIcon: "zap",
			Filename:     filename,
			Type:         DownloadTypeMagnet,
			IsTorrent:    true,
		}, nil
	}

	cleanURL, authHeader, err := ExtractBasicAuth(norm)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	u, err := url.Parse(cleanURL)
	if err != nil {
		return nil, fmt.Errorf("cannot parse URL: %w", err)
	}

	host := strings.ToLower(u.Host)
	hostname := u.Hostname()

	// Default fallback values
	res := &ResolvedLink{
		OriginalURL:  rawInput,
		ResolvedURL:  cleanURL,
		Domain:       hostname,
		Provider:     hostname,
		ProviderIcon: "download",
		Filename:     ParseFilenameFromHeaders("", cleanURL),
		AuthHeader:   authHeader,
		Type:         DownloadTypeDirect,
	}

	// Detect .torrent HTTP URL
	cleanPath := strings.ToLower(u.Path)
	if strings.HasSuffix(cleanPath, ".torrent") {
		res.Provider = "BitTorrent (.torrent)"
		res.ProviderIcon = "zap"
		res.IsTorrent = true
		return res, nil
	}

	// 1. Google Drive
	if strings.HasSuffix(host, "drive.google.com") || strings.HasSuffix(host, "docs.google.com") {
		res.Provider = "Google Drive"
		res.ProviderIcon = "google"

		fileID := ""
		if match := gdriveFileIDRegex.FindStringSubmatch(u.Path); len(match) == 2 {
			fileID = match[1]
		} else if qID := u.Query().Get("id"); qID != "" {
			fileID = qID
		}

		if fileID != "" {
			res.ResolvedURL = fmt.Sprintf("https://drive.google.com/uc?export=download&id=%s&confirm=t", fileID)
			res.Filename = fmt.Sprintf("gdrive_%s.bin", fileID[:8])
		}
		return res, nil
	}

	// 2. Dropbox
	if strings.HasSuffix(host, "dropbox.com") {
		res.Provider = "Dropbox"
		res.ProviderIcon = "dropbox"

		q := u.Query()
		if q.Get("dl") != "1" {
			q.Set("dl", "1")
			u.RawQuery = q.Encode()
			res.ResolvedURL = u.String()
		}
		return res, nil
	}

	// 3. GitHub
	if strings.HasSuffix(host, "github.com") {
		res.Provider = "GitHub"
		res.ProviderIcon = "github"

		// GitHub blob URL -> raw.githubusercontent.com
		if match := githubBlobRegex.FindStringSubmatch(u.Path); len(match) == 5 {
			owner, repo, branch, filePath := match[1], match[2], match[3], match[4]
			res.ResolvedURL = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s", owner, repo, branch, filePath)
			res.Filename = path.Base(filePath)
			return res, nil
		}

		// GitHub Gist
		if strings.HasPrefix(host, "gist.github.com") {
			parts := strings.Split(strings.Trim(u.Path, "/"), "/")
			if len(parts) >= 2 {
				res.ResolvedURL = fmt.Sprintf("https://gist.githubusercontent.com/%s/%s/raw", parts[0], parts[1])
				res.Filename = parts[1] + ".txt"
				return res, nil
			}
		}

		return res, nil
	}

	// 4. GitLab
	if strings.HasSuffix(host, "gitlab.com") {
		res.Provider = "GitLab"
		res.ProviderIcon = "git"

		if match := gitlabBlobRegex.FindStringSubmatch(u.Path); len(match) == 5 {
			owner, repo, branch, filePath := match[1], match[2], match[3], match[4]
			res.ResolvedURL = fmt.Sprintf("https://gitlab.com/%s/%s/-/raw/%s/%s", owner, repo, branch, filePath)
			res.Filename = path.Base(filePath)
			return res, nil
		}
		return res, nil
	}

	// 5. Bitbucket
	if strings.HasSuffix(host, "bitbucket.org") {
		res.Provider = "Bitbucket"
		res.ProviderIcon = "git"

		if match := bitbucketSrcRegex.FindStringSubmatch(u.Path); len(match) == 5 {
			owner, repo, branch, filePath := match[1], match[2], match[3], match[4]
			res.ResolvedURL = fmt.Sprintf("https://bitbucket.org/%s/%s/raw/%s/%s", owner, repo, branch, filePath)
			res.Filename = path.Base(filePath)
			return res, nil
		}
		return res, nil
	}

	// 6. Hugging Face
	if strings.HasSuffix(host, "huggingface.co") {
		res.Provider = "Hugging Face"
		res.ProviderIcon = "box"

		if match := huggingfaceRegex.FindStringSubmatch(u.Path); len(match) == 5 {
			owner, repo, branch, filePath := match[1], match[2], match[3], match[4]
			res.ResolvedURL = fmt.Sprintf("https://huggingface.co/%s/%s/resolve/%s/%s?download=true", owner, repo, branch, filePath)
			res.Filename = path.Base(filePath)
			return res, nil
		}
		return res, nil
	}

	// 7. OneDrive / 1drv.ms
	if strings.HasSuffix(host, "1drv.ms") || strings.HasSuffix(host, "onedrive.live.com") {
		res.Provider = "OneDrive"
		res.ProviderIcon = "cloud"

		q := u.Query()
		if q.Get("download") != "1" {
			q.Set("download", "1")
			u.RawQuery = q.Encode()
			res.ResolvedURL = u.String()
		}
		return res, nil
	}

	// 8. SourceForge
	if strings.HasSuffix(host, "sourceforge.net") {
		res.Provider = "SourceForge"
		res.ProviderIcon = "download"

		if strings.HasSuffix(u.Path, "/download") {
			q := u.Query()
			if q.Get("use_mirror") == "" {
				q.Set("use_mirror", "autoselect")
				u.RawQuery = q.Encode()
				res.ResolvedURL = u.String()
			}
		}
		return res, nil
	}

	// 9. Pastebin
	if strings.HasSuffix(host, "pastebin.com") {
		res.Provider = "Pastebin"
		res.ProviderIcon = "code"

		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) == 1 && parts[0] != "" && parts[0] != "raw" {
			res.ResolvedURL = fmt.Sprintf("https://pastebin.com/raw/%s", parts[0])
			res.Filename = parts[0] + ".txt"
			return res, nil
		}
	}

	// 10. Archive.org
	if strings.HasSuffix(host, "archive.org") {
		res.Provider = "Internet Archive"
		res.ProviderIcon = "archive"
		return res, nil
	}

	// 11. MediaFire
	if strings.Contains(host, "mediafire.com") {
		res.Provider = "MediaFire"
		res.ProviderIcon = "fire"
		res.Referer = "https://www.mediafire.com/"

		var fileKey string
		var extractedName string

		pathParts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if strings.HasPrefix(host, "download") {
			// Pattern: downloadXXXX.mediafire.com/<token>/<key>/<filename>
			if len(pathParts) >= 3 {
				fileKey = pathParts[1]
				extractedName = pathParts[2]
			} else if len(pathParts) == 2 {
				fileKey = pathParts[0]
				extractedName = pathParts[1]
			}
		} else {
			// Pattern: mediafire.com/file/<key>/<filename> or /download/<key>/<filename>
			if len(pathParts) >= 2 && (pathParts[0] == "file" || pathParts[0] == "download" || pathParts[0] == "file_premium") {
				fileKey = pathParts[1]
				if len(pathParts) >= 3 && pathParts[2] != "file" {
					extractedName = pathParts[2]
				}
			}
		}

		if extractedName != "" {
			if unescaped, err := url.PathUnescape(extractedName); err == nil {
				res.Filename = CleanFilename(unescaped, res.Filename)
			}
		}

		// If this is a sharing landing page, attempt to resolve the direct CDN download link
		if !strings.HasPrefix(host, "download") && fileKey != "" {
			shareURL := fmt.Sprintf("https://www.mediafire.com/file/%s/", fileKey)
			if directLink, scrapedName, err := FetchMediaFireDirectLink(shareURL); err == nil && directLink != "" {
				res.ResolvedURL = directLink
				if scrapedName != "" {
					res.Filename = CleanFilename(scrapedName, res.Filename)
				}
			}
		}

		return res, nil
	}

	return res, nil
}

var (
	genericDownloadBtnRegex  = regexp.MustCompile(`(?i)(?:id=["']downloadButton["']|aria-label=["']Download[^"']*["'])[^>]*href=["']([^"']+)["']`)
	genericDownloadHrefRegex = regexp.MustCompile(`(?i)href=["']([^"']+)["'][^>]*(?:id=["']downloadButton["']|aria-label=["']Download[^"']*["'])`)
)

// ExtractMediaFireDirectLinkFromHTML scans an HTML page for direct MediaFire download links and filename.
func ExtractMediaFireDirectLinkFromHTML(htmlContent string) (string, string) {
	directURL := ""
	if match := mediafireBtnRegex.FindStringSubmatch(htmlContent); len(match) == 2 {
		directURL = match[1]
	} else if match := mediafireRawCdnRegex.FindString(htmlContent); match != "" {
		directURL = match
	} else if match := genericDownloadBtnRegex.FindStringSubmatch(htmlContent); len(match) == 2 {
		directURL = match[1]
	} else if match := genericDownloadHrefRegex.FindStringSubmatch(htmlContent); len(match) == 2 {
		directURL = match[1]
	}

	filename := ""
	if match := mediafireTitleRegex.FindStringSubmatch(htmlContent); len(match) == 2 {
		clean := strings.TrimSpace(match[1])
		if clean != "" && !strings.Contains(clean, "MediaFire") {
			filename = clean
		}
	}
	if filename == "" && directURL != "" {
		if u, err := url.Parse(directURL); err == nil {
			filename = path.Base(u.Path)
		}
	}

	return directURL, filename
}

// ExtractGoogleDriveConfirmLinkFromHTML scans an HTML warning page for the confirmation download link.
func ExtractGoogleDriveConfirmLinkFromHTML(htmlContent string) string {
	if match := gdriveConfirmUrlRegex.FindStringSubmatch(htmlContent); len(match) == 2 {
		return strings.ReplaceAll(match[1], "&amp;", "&")
	}
	if match := gdriveConfirmRegex.FindStringSubmatch(htmlContent); len(match) == 2 {
		return "https://drive.google.com" + strings.ReplaceAll(match[1], "&amp;", "&")
	}
	return ""
}

// FetchMediaFireDirectLink attempts to fetch the MediaFire share page and extract the direct CDN download URL.
// In restricted network or offline environments, it fails gracefully without blocking.
func FetchMediaFireDirectLink(shareURL string) (string, string, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	req, err := http.NewRequest(http.MethodGet, shareURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", DefaultBrowserUserAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Referer", "https://www.mediafire.com/")

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return "", "", err
	}

	directURL, filename := ExtractMediaFireDirectLinkFromHTML(string(bodyBytes))
	if directURL == "" {
		return "", "", fmt.Errorf("direct download button not found in page")
	}
	return directURL, filename, nil
}
