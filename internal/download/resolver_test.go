package download

import (
	"strings"
	"testing"
)

func TestNormalizeLink(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "scheme-less URL with path",
			input:    "releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso",
			expected: "https://releases.ubuntu.com/24.04/ubuntu-24.04-desktop-amd64.iso",
		},
		{
			name:     "scheme-less github link",
			input:    "github.com/golang/go/blob/master/README.md",
			expected: "https://github.com/golang/go/blob/master/README.md",
		},
		{
			name:     "quoted link",
			input:    `"https://example.com/file.zip"`,
			expected: "https://example.com/file.zip",
		},
		{
			name:     "single-quoted link",
			input:    `'https://example.com/file.iso'`,
			expected: "https://example.com/file.iso",
		},
		{
			name:     "markdown wrapped link",
			input:    "[Download Link](https://cdn.example.org/archive.tar.gz)",
			expected: "https://cdn.example.org/archive.tar.gz",
		},
		{
			name:     "angle bracket wrapped link",
			input:    "<https://cdn.example.org/doc.pdf>",
			expected: "https://cdn.example.org/doc.pdf",
		},
		{
			name:     "magnet link preserved",
			input:    "  magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=sample.iso  ",
			expected: "magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=sample.iso",
		},
		{
			name:     "google redirect unwrapped",
			input:    "https://www.google.com/url?q=https://example.com/target.zip&sa=D",
			expected: "https://example.com/target.zip",
		},
		{
			name:     "href.li anonymizer unwrapped",
			input:    "https://href.li/?https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz",
			expected: "https://mirrors.edge.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz",
		},
		{
			name:     "empty input",
			input:    "",
			expected: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := NormalizeLink(tc.input)
			if got != tc.expected {
				t.Errorf("NormalizeLink(%q) = %q; expected %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestExtractBasicAuth(t *testing.T) {
	raw := "https://alice:secret123@storage.internal.org/data/backup.sql"
	cleanURL, authHeader, err := ExtractBasicAuth(raw)
	if err != nil {
		t.Fatalf("ExtractBasicAuth failed: %v", err)
	}

	if strings.Contains(cleanURL, "secret123") || strings.Contains(cleanURL, "alice") {
		t.Errorf("Credentials leaked in clean URL: %s", cleanURL)
	}

	if !strings.HasPrefix(authHeader, "Basic ") {
		t.Errorf("Expected Basic auth header, got %s", authHeader)
	}
}

func TestResolveLink_DomainResolvers(t *testing.T) {
	tests := []struct {
		name             string
		input            string
		expectedProvider string
		expectedURLPart  string
		expectedName     string
		isTorrent        bool
	}{
		{
			name:             "Google Drive file/d/view link",
			input:            "https://drive.google.com/file/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs/view?usp=sharing",
			expectedProvider: "Google Drive",
			expectedURLPart:  "export=download&id=1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs&confirm=t",
			expectedName:     "gdrive_1BxiMVs0.bin",
		},
		{
			name:             "Dropbox view link dl=0",
			input:            "https://www.dropbox.com/s/xyz123/monthly_report.xlsx?dl=0",
			expectedProvider: "Dropbox",
			expectedURLPart:  "dl=1",
			expectedName:     "monthly_report.xlsx",
		},
		{
			name:             "GitHub blob to raw link",
			input:            "https://github.com/golang/go/blob/master/README.md",
			expectedProvider: "GitHub",
			expectedURLPart:  "raw.githubusercontent.com/golang/go/master/README.md",
			expectedName:     "README.md",
		},
		{
			name:             "GitHub Gist link",
			input:            "https://gist.github.com/torvalds/12345678",
			expectedProvider: "GitHub",
			expectedURLPart:  "gist.githubusercontent.com/torvalds/12345678/raw",
			expectedName:     "12345678.txt",
		},
		{
			name:             "GitLab blob to raw link",
			input:            "https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/models/user.rb",
			expectedProvider: "GitLab",
			expectedURLPart:  "gitlab.com/gitlab-org/gitlab/-/raw/master/app/models/user.rb",
			expectedName:     "user.rb",
		},
		{
			name:             "Bitbucket src to raw link",
			input:            "https://bitbucket.org/atlassian/repo/src/master/config.json",
			expectedProvider: "Bitbucket",
			expectedURLPart:  "bitbucket.org/atlassian/repo/raw/master/config.json",
			expectedName:     "config.json",
		},
		{
			name:             "Hugging Face model weights",
			input:            "https://huggingface.co/meta-llama/Llama-2-7b/blob/main/pytorch_model.bin",
			expectedProvider: "Hugging Face",
			expectedURLPart:  "resolve/main/pytorch_model.bin?download=true",
			expectedName:     "pytorch_model.bin",
		},
		{
			name:             "SourceForge download mirror link",
			input:            "https://sourceforge.net/projects/sevenzip/files/7-Zip/23.01/7z2301-x64.exe/download",
			expectedProvider: "SourceForge",
			expectedURLPart:  "use_mirror=autoselect",
			expectedName:     "download",
		},
		{
			name:             "Pastebin raw link",
			input:            "https://pastebin.com/d9jKhw1Q",
			expectedProvider: "Pastebin",
			expectedURLPart:  "pastebin.com/raw/d9jKhw1Q",
			expectedName:     "d9jKhw1Q.txt",
		},
		{
			name:             ".torrent HTTP URL",
			input:            "https://cdimage.debian.org/debian-cd/current/amd64/bt-cd/debian-12.5.0-amd64-netinst.iso.torrent",
			expectedProvider: "BitTorrent (.torrent)",
			expectedURLPart:  "debian-12.5.0-amd64-netinst.iso.torrent",
			expectedName:     "debian-12.5.0-amd64-netinst.iso.torrent",
			isTorrent:        true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ResolveLink(tc.input)
			if err != nil {
				t.Fatalf("ResolveLink failed: %v", err)
			}

			if res.Provider != tc.expectedProvider {
				t.Errorf("Expected provider %q, got %q", tc.expectedProvider, res.Provider)
			}

			if !strings.Contains(res.ResolvedURL, tc.expectedURLPart) {
				t.Errorf("Resolved URL %q does not contain expected part %q", res.ResolvedURL, tc.expectedURLPart)
			}

			if tc.expectedName != "" && res.Filename != tc.expectedName {
				t.Errorf("Expected filename %q, got %q", tc.expectedName, res.Filename)
			}

			if res.IsTorrent != tc.isTorrent {
				t.Errorf("Expected IsTorrent=%v, got %v", tc.isTorrent, res.IsTorrent)
			}
		})
	}
}
