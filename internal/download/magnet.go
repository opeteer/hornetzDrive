package download

import (
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// MagnetInfo holds parsed metadata from a BitTorrent magnet URI.
type MagnetInfo struct {
	InfoHash     [20]byte `json:"info_hash"`
	HexHash      string   `json:"hex_hash"`
	DisplayName  string   `json:"display_name"`
	Trackers     []string `json:"trackers"`
	WebSeeds     []string `json:"web_seeds"`
	ExactSources []string `json:"exact_sources"`
	ExactLength  int64    `json:"exact_length"`
	PieceLength  int64    `json:"piece_length,omitempty"`
}

// ParseMagnetURI parses and validates a BitTorrent magnet link (BEP 9 / BEP 53).
func ParseMagnetURI(rawURI string) (*MagnetInfo, error) {
	rawURI = strings.TrimSpace(rawURI)
	if !strings.HasPrefix(rawURI, "magnet:?") {
		return nil, errors.New("invalid magnet link: must start with 'magnet:?'")
	}

	u, err := url.Parse(rawURI)
	if err != nil {
		return nil, fmt.Errorf("malformed magnet link: %w", err)
	}

	q := u.Query()
	xts := q["xt"]
	if len(xts) == 0 {
		return nil, errors.New("invalid magnet link: missing exact topic 'xt' parameter")
	}

	var infoHash [20]byte
	var hexHash string
	foundBTIH := false

	for _, xt := range xts {
		if strings.HasPrefix(strings.ToLower(xt), "urn:btih:") {
			rawHash := strings.TrimPrefix(xt, "urn:btih:")
			rawHash = strings.TrimPrefix(rawHash, "URN:BTIH:")
			rawHash = strings.TrimSpace(rawHash)

			if len(rawHash) == 40 {
				decoded, err := hex.DecodeString(rawHash)
				if err == nil && len(decoded) == 20 {
					copy(infoHash[:], decoded)
					hexHash = strings.ToLower(rawHash)
					foundBTIH = true
					break
				}
			} else if len(rawHash) == 32 {
				// Base32 encoded (RFC 4648)
				decoded, err := base32.StdEncoding.DecodeString(strings.ToUpper(rawHash))
				if err == nil && len(decoded) == 20 {
					copy(infoHash[:], decoded)
					hexHash = hex.EncodeToString(decoded)
					foundBTIH = true
					break
				}
			}
		}
	}

	if !foundBTIH {
		return nil, errors.New("invalid magnet link: missing or malformed BTIH hash in 'xt'")
	}

	info := &MagnetInfo{
		InfoHash: infoHash,
		HexHash:  hexHash,
	}

	// Display Name (dn)
	if dn := q.Get("dn"); dn != "" {
		info.DisplayName = CleanFilename(dn, "")
	} else {
		info.DisplayName = fmt.Sprintf("torrent_%s", hexHash[:8])
	}

	// Trackers (tr)
	for _, tr := range q["tr"] {
		tr = strings.TrimSpace(tr)
		if tr != "" {
			info.Trackers = append(info.Trackers, tr)
		}
	}

	// Web Seeds (ws) - BEP 19
	for _, ws := range q["ws"] {
		ws = strings.TrimSpace(ws)
		if ws != "" {
			info.WebSeeds = append(info.WebSeeds, ws)
		}
	}

	// Exact Sources (xs)
	for _, xs := range q["xs"] {
		xs = strings.TrimSpace(xs)
		if xs != "" {
			info.ExactSources = append(info.ExactSources, xs)
		}
	}

	// Exact Length (xl)
	if xl := q.Get("xl"); xl != "" {
		if size, err := strconv.ParseInt(xl, 10, 64); err == nil && size >= 0 {
			info.ExactLength = size
		}
	}

	// Piece Length (pl)
	if pl := q.Get("pl"); pl != "" {
		if pLen, err := strconv.ParseInt(pl, 10, 64); err == nil && pLen > 0 {
			info.PieceLength = pLen
		}
	}

	return info, nil
}
