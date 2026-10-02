package scanner

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"
)

var (
	// Suspicious script patterns in SVG / XML / HTML / Polyglots
	svgScriptPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?is)<\s*script\b[^>]*>`),
		regexp.MustCompile(`(?is)<\s*/\s*script\s*>`),
		regexp.MustCompile(`(?i)javascript\s*:`),
		regexp.MustCompile(`(?i)data:text/html`),
		regexp.MustCompile(`(?i)\bon(load|error|click|focus|blur|mouse\w+|key\w+)\s*=`),
		regexp.MustCompile(`(?is)<\s*(iframe|object|embed|applet)\b[^>]*>`),
		regexp.MustCompile(`(?i)<!ENTITY`), // XXE injection
	}

	// Server-side script tags embedded in uploaded assets (PHP, ASP, JSP)
	webShellPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)<\?php`),
		regexp.MustCompile(`(?i)<\?=`),
		regexp.MustCompile(`(?i)<%@`),
		regexp.MustCompile(`(?i)<jsp:`),
	}
)

// HeuristicConfig configures the static heuristic scanner.
type HeuristicConfig struct {
	// BlockExecutables blocks PE, ELF, Mach-O, and Shebang binaries in non-executable files (default: true).
	BlockExecutables bool
	// BlockSVGScripts blocks embedded JavaScript and event handlers in SVGs (default: true).
	BlockSVGScripts bool
	// BlockWebShells blocks embedded PHP/ASP/JSP tags (default: true).
	BlockWebShells bool
	// BlockZipSlip blocks ZIP files containing directory traversal entries (default: true).
	BlockZipSlip bool
	// MaxZipRatio blocks ZIP files with excessive compression ratio (zip bomb defense) (default: 100.0).
	MaxZipRatio float64
	// DisallowOfficeMacros blocks OOXML Office documents containing VBA macros (default: true).
	DisallowOfficeMacros bool
}

// DefaultHeuristicConfig returns the zero-trust default heuristic configuration.
func DefaultHeuristicConfig() HeuristicConfig {
	return HeuristicConfig{
		BlockExecutables:     true,
		BlockSVGScripts:      true,
		BlockWebShells:       true,
		BlockZipSlip:         true,
		MaxZipRatio:          100.0,
		DisallowOfficeMacros: true,
	}
}

// HeuristicScanner performs static signature and heuristic analysis on file streams.
type HeuristicScanner struct {
	cfg HeuristicConfig
}

// NewHeuristicScanner initializes a new HeuristicScanner with default settings.
func NewHeuristicScanner() *HeuristicScanner {
	return NewHeuristicScannerWithConfig(DefaultHeuristicConfig())
}

// NewHeuristicScannerWithConfig initializes a HeuristicScanner with custom settings.
func NewHeuristicScannerWithConfig(cfg HeuristicConfig) *HeuristicScanner {
	if cfg.MaxZipRatio <= 0 {
		cfg.MaxZipRatio = 100.0
	}
	return &HeuristicScanner{cfg: cfg}
}

// Scan inspects the provided file data for malicious heuristic patterns.
func (s *HeuristicScanner) Scan(ctx context.Context, r io.ReaderAt, size int64, info FileInfo) (*ScanResult, error) {
	if size <= 0 {
		return &ScanResult{Clean: true, ScannerName: "Heuristic"}, nil
	}

	headerSize := int64(4096)
	if size < headerSize {
		headerSize = size
	}
	headerBuf := make([]byte, headerSize)
	if _, err := r.ReadAt(headerBuf, 0); err != nil && err != io.EOF {
		return nil, err
	}

	ext := strings.ToLower(info.Extension)
	mime := strings.ToLower(info.MIME)

	// 1. Check for dangerous executable binary headers disguised as non-executables
	if s.cfg.BlockExecutables && !isAllowedExecutableType(ext, mime) {
		if threat := checkExecutableHeaders(headerBuf); threat != "" {
			return &ScanResult{
				Clean:       false,
				ThreatName:  threat,
				ScannerName: "Heuristic",
				Details: map[string]any{
					"reason": "disguised_executable_binary",
				},
			}, nil
		}
	}

	// 2. Check for web shells in images / media / text
	if s.cfg.BlockWebShells && !isScriptExtension(ext) {
		inspectSize := int64(64 * 1024)
		if size < inspectSize {
			inspectSize = size
		}
		inspectBuf := make([]byte, inspectSize)
		_, _ = r.ReadAt(inspectBuf, 0)

		for _, pat := range webShellPatterns {
			if pat.Match(inspectBuf) {
				return &ScanResult{
					Clean:       false,
					ThreatName:  "Embedded.WebShell.ScriptTag",
					ScannerName: "Heuristic",
					Details: map[string]any{
						"pattern": pat.String(),
					},
				}, nil
			}
		}
	}

	// 3. Deep SVG / XML inspection
	if s.cfg.BlockSVGScripts && (ext == ".svg" || strings.Contains(mime, "svg") || strings.Contains(mime, "xml")) {
		inspectSize := size
		if inspectSize > 512*1024 { // Scan up to 512KB of SVG
			inspectSize = 512 * 1024
		}
		svgBuf := make([]byte, inspectSize)
		_, _ = r.ReadAt(svgBuf, 0)

		for _, pat := range svgScriptPatterns {
			if pat.Match(svgBuf) {
				return &ScanResult{
					Clean:       false,
					ThreatName:  "Script.Injection.SVG_XML",
					ScannerName: "Heuristic",
					Details: map[string]any{
						"pattern": pat.String(),
					},
				}, nil
			}
		}
	}

	// 4. ZIP Archive Inspection (Zip Slip & Decompression Bombs & Macros)
	if ext == ".zip" || ext == ".docx" || ext == ".xlsx" || ext == ".pptx" || strings.Contains(mime, "zip") {
		zr, err := zip.NewReader(r, size)
		if err == nil {
			var totalUncompressed uint64
			for _, f := range zr.File {
				// Zip Slip directory traversal check
				if s.cfg.BlockZipSlip {
					name := f.Name
					if strings.Contains(name, "..") || strings.HasPrefix(name, "/") || strings.HasPrefix(name, "\\") {
						return &ScanResult{
							Clean:       false,
							ThreatName:  "Archive.ZipSlip.PathTraversal",
							ScannerName: "Heuristic",
							Details:     map[string]any{"entry": name},
						}, nil
					}
				}

				// Office Macro check
				if s.cfg.DisallowOfficeMacros {
					lowName := strings.ToLower(f.Name)
					if strings.Contains(lowName, "vbaproject.bin") || strings.Contains(lowName, "vba_project") {
						return &ScanResult{
							Clean:       false,
							ThreatName:  "Office.MaliciousMacro.VBA",
							ScannerName: "Heuristic",
							Details:     map[string]any{"entry": f.Name},
						}, nil
					}
				}

				totalUncompressed += f.UncompressedSize64
			}

			// Zip Bomb check
			if s.cfg.MaxZipRatio > 0 && size > 1024 {
				ratio := float64(totalUncompressed) / float64(size)
				if ratio > s.cfg.MaxZipRatio && totalUncompressed > 50*1024*1024 {
					return &ScanResult{
						Clean:       false,
						ThreatName:  "Archive.DecompressionBomb.ZipBomb",
						ScannerName: "Heuristic",
						Details: map[string]any{
							"ratio":              ratio,
							"uncompressed_bytes": totalUncompressed,
						},
					}, nil
				}
			}
		}
	}

	return &ScanResult{
		Clean:       true,
		ScannerName: "Heuristic",
	}, nil
}

func checkExecutableHeaders(buf []byte) string {
	if len(buf) < 4 {
		return ""
	}

	// Windows PE: MZ
	if buf[0] == 0x4D && buf[1] == 0x5A {
		return "Executable.PE.Windows"
	}

	// Linux ELF: \x7fELF
	if bytes.HasPrefix(buf, []byte{0x7F, 0x45, 0x4C, 0x46}) {
		return "Executable.ELF.Linux"
	}

	// Mach-O (32-bit & 64-bit, big & little endian)
	if bytes.HasPrefix(buf, []byte{0xFE, 0xED, 0xFA, 0xCE}) ||
		bytes.HasPrefix(buf, []byte{0xFE, 0xED, 0xFA, 0xCF}) ||
		bytes.HasPrefix(buf, []byte{0xCE, 0xFA, 0xED, 0xFE}) ||
		bytes.HasPrefix(buf, []byte{0xCF, 0xFA, 0xED, 0xFE}) {
		return "Executable.MachO.macOS"
	}

	// Java Class Bytecode: 0xCAFEBABE
	if bytes.HasPrefix(buf, []byte{0xCA, 0xFE, 0xBA, 0xBE}) {
		return "Executable.JavaClass"
	}

	// Shebang
	if bytes.HasPrefix(buf, []byte{'#', '!'}) {
		return "Executable.Script.Shebang"
	}

	return ""
}

func isAllowedExecutableType(ext, mime string) bool {
	return ext == ".exe" || ext == ".bin" || ext == ".sh" ||
		mime == "application/x-executable" || mime == "application/x-msdownload"
}

func isScriptExtension(ext string) bool {
	return ext == ".php" || ext == ".asp" || ext == ".aspx" || ext == ".jsp" ||
		ext == ".sh" || ext == ".bat" || ext == ".ps1"
}
