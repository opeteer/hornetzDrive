package download

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// TorrentClient manages BitTorrent downloads from magnet URIs.
type TorrentClient struct {
	HTTPClient *http.Client
	PeerID     [20]byte
}

func NewTorrentClient() *TorrentClient {
	var peerID [20]byte
	copy(peerID[:8], []byte("-HZ2000-")) // Hornetz Drive v2.0
	_, _ = rand.Read(peerID[8:])

	return &TorrentClient{
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		PeerID: peerID,
	}
}

// DownloadTorrent handles downloading payload from a magnet link into destWriter.
// It prioritizes Web Seeds (BEP 19) when available, and falls back to BitTorrent tracker/peer protocol.
func (tc *TorrentClient) DownloadTorrent(ctx context.Context, info *MagnetInfo, destWriter io.Writer, onProgress func(downloaded int64, total int64, speed string)) error {
	// 1. Try Web Seeds (BEP 19) or Exact Sources (xs) if present
	for _, wsURL := range append(info.WebSeeds, info.ExactSources...) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		err := tc.downloadFromWebSeed(ctx, wsURL, info, destWriter, onProgress)
		if err == nil {
			return nil
		}
	}

	// 2. Query HTTP Trackers for Peers
	var peers []string
	for _, trURL := range info.Trackers {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if strings.HasPrefix(trURL, "http://") || strings.HasPrefix(trURL, "https://") {
			foundPeers, err := tc.announceHTTPTracker(ctx, trURL, info)
			if err == nil && len(foundPeers) > 0 {
				peers = append(peers, foundPeers...)
			}
		}
	}

	// 3. Connect to peers and download
	if len(peers) > 0 {
		for _, peerAddr := range peers {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			err := tc.downloadFromPeer(ctx, peerAddr, info, destWriter, onProgress)
			if err == nil {
				return nil
			}
		}
	}

	// If no peers or web seeds succeeded
	if len(info.WebSeeds) == 0 && len(info.Trackers) == 0 {
		return errors.New("magnet link contains neither web seeds nor reachable trackers")
	}

	return fmt.Errorf("unable to establish peer connections or retrieve metadata for info_hash %s (all peers timed out)", info.HexHash[:8])
}

func (tc *TorrentClient) downloadFromWebSeed(ctx context.Context, wsURL string, info *MagnetInfo, destWriter io.Writer, onProgress func(downloaded int64, total int64, speed string)) error {
	targetURL := wsURL
	// In BEP 19, if web seed ends in '/', append display name
	if strings.HasSuffix(targetURL, "/") && info.DisplayName != "" {
		targetURL += url.PathEscape(info.DisplayName)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "HornetzDrive/2.0 (BitTorrent WebSeed)")

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("web seed returned HTTP %d", resp.StatusCode)
	}

	total := resp.ContentLength
	if total <= 0 && info.ExactLength > 0 {
		total = info.ExactLength
	}

	return streamWithProgress(ctx, resp.Body, destWriter, total, onProgress)
}

func (tc *TorrentClient) announceHTTPTracker(ctx context.Context, trackerURL string, info *MagnetInfo) ([]string, error) {
	u, err := url.Parse(trackerURL)
	if err != nil {
		return nil, err
	}

	q := u.Query()
	q.Set("info_hash", string(info.InfoHash[:]))
	q.Set("peer_id", string(tc.PeerID[:]))
	q.Set("port", "6881")
	q.Set("uploaded", "0")
	q.Set("downloaded", "0")
	q.Set("left", fmt.Sprintf("%d", info.ExactLength))
	q.Set("compact", "1")
	q.Set("event", "started")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "HornetzDrive/2.0")

	resp, err := tc.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("tracker returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}

	parsed, err := UnmarshalBencode(body)
	if err != nil {
		return nil, err
	}

	dict, ok := parsed.(map[string]interface{})
	if !ok {
		return nil, errors.New("invalid tracker response: not a dictionary")
	}

	if failReason, ok := dict["failure reason"].(string); ok && failReason != "" {
		return nil, fmt.Errorf("tracker failure: %s", failReason)
	}

	var peers []string
	// Binary compact format (6 bytes per peer: 4-byte IPv4 + 2-byte port)
	if peersStr, ok := dict["peers"].(string); ok {
		peersBytes := []byte(peersStr)
		for i := 0; i+6 <= len(peersBytes); i += 6 {
			ip := net.IP(peersBytes[i : i+4])
			port := binary.BigEndian.Uint16(peersBytes[i+4 : i+6])
			peers = append(peers, fmt.Sprintf("%s:%d", ip.String(), port))
		}
	} else if peerList, ok := dict["peers"].([]interface{}); ok {
		// Non-compact dictionary list
		for _, p := range peerList {
			if pDict, ok := p.(map[string]interface{}); ok {
				ip, _ := pDict["ip"].(string)
				port, _ := pDict["port"].(int64)
				if ip != "" && port > 0 {
					peers = append(peers, fmt.Sprintf("%s:%d", ip, port))
				}
			}
		}
	}

	return peers, nil
}

func (tc *TorrentClient) downloadFromPeer(ctx context.Context, peerAddr string, info *MagnetInfo, destWriter io.Writer, onProgress func(downloaded int64, total int64, speed string)) error {
	d := net.Dialer{Timeout: 5 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", peerAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Send BitTorrent Handshake (68 bytes: 1 + 19 + 8 + 20 + 20)
	var handshake [68]byte
	handshake[0] = 19
	copy(handshake[1:20], []byte("BitTorrent protocol"))
	handshake[25] = 0x10 // BEP 10 extension bit
	copy(handshake[28:48], info.InfoHash[:])
	copy(handshake[48:68], tc.PeerID[:])

	if _, err := conn.Write(handshake[:]); err != nil {
		return err
	}

	// Read Peer Handshake
	var peerHandshake [68]byte
	if _, err := io.ReadFull(conn, peerHandshake[:]); err != nil {
		return err
	}

	if peerHandshake[0] != 19 || string(peerHandshake[1:20]) != "BitTorrent protocol" {
		return errors.New("invalid peer protocol handshake")
	}

	if !bytes.Equal(peerHandshake[28:48], info.InfoHash[:]) {
		return errors.New("peer handshake info_hash mismatch")
	}

	// Send Extension Handshake (BEP 10)
	extDict := map[string]interface{}{
		"m": map[string]interface{}{
			"ut_metadata": 1,
		},
	}
	extBytes, err := MarshalBencode(extDict)
	if err != nil {
		return err
	}

	extMsg := make([]byte, 4+1+1+len(extBytes))
	binary.BigEndian.PutUint32(extMsg[0:4], uint32(2+len(extBytes)))
	extMsg[4] = 20 // Extended message ID
	extMsg[5] = 0  // Handshake extension ID
	copy(extMsg[6:], extBytes)

	if _, err := conn.Write(extMsg); err != nil {
		return err
	}

	// Send Interested message (ID = 2)
	interested := []byte{0, 0, 0, 1, 2}
	if _, err := conn.Write(interested); err != nil {
		return err
	}

	// Read peer messages with timeout
	startTime := time.Now()
	var downloaded int64
	total := info.ExactLength

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

		var msgLenBuf [4]byte
		if _, err := io.ReadFull(conn, msgLenBuf[:]); err != nil {
			break
		}
		msgLen := binary.BigEndian.Uint32(msgLenBuf[:])
		if msgLen == 0 {
			// Keep-alive message
			continue
		}
		if msgLen > 10*1024*1024 {
			return errors.New("peer message too large")
		}

		msgData := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, msgData); err != nil {
			return err
		}

		msgID := msgData[0]
		switch msgID {
		case 1:
			// Unchoke - peer is ready for requests!
		case 7:
			// Piece payload: index(4) + begin(4) + block data
			if len(msgData) > 9 {
				block := msgData[9:]
				if _, err := destWriter.Write(block); err != nil {
					return err
				}
				downloaded += int64(len(block))

				if onProgress != nil {
					elapsed := time.Since(startTime).Seconds()
					speed := "0.0 MB/s"
					if elapsed > 0.05 {
						mbps := (float64(downloaded) / (1024 * 1024)) / elapsed
						speed = fmt.Sprintf("%.1f MB/s", mbps)
					}
					onProgress(downloaded, total, speed)
				}
			}
		}

		if total > 0 && downloaded >= total {
			break
		}
	}

	if downloaded > 0 {
		return nil
	}

	return errors.New("no payload data received from peer")
}

func streamWithProgress(ctx context.Context, src io.Reader, dst io.Writer, total int64, onProgress func(downloaded int64, total int64, speed string)) error {
	buf := make([]byte, 64*1024)
	var downloaded int64
	startTime := time.Now()
	lastUpdate := time.Now()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := src.Read(buf)
		if n > 0 {
			if _, wErr := dst.Write(buf[:n]); wErr != nil {
				return wErr
			}
			downloaded += int64(n)

			now := time.Now()
			if onProgress != nil && now.Sub(lastUpdate) >= 150*time.Millisecond {
				elapsed := now.Sub(startTime).Seconds()
				speed := "0.0 MB/s"
				if elapsed > 0.05 {
					mbps := (float64(downloaded) / (1024 * 1024)) / elapsed
					speed = fmt.Sprintf("%.1f MB/s", mbps)
				}
				onProgress(downloaded, total, speed)
				lastUpdate = now
			}
		}

		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}

	if onProgress != nil {
		elapsed := time.Since(startTime).Seconds()
		speed := "0.0 MB/s"
		if elapsed > 0.05 {
			mbps := (float64(downloaded) / (1024 * 1024)) / elapsed
			speed = fmt.Sprintf("%.1f MB/s", mbps)
		}
		onProgress(downloaded, total, speed)
	}

	return nil
}
