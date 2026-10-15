package download

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTorrentClient_DownloadViaWebSeed(t *testing.T) {
	fileContent := []byte("BitTorrent BEP 19 Web Seed payload content verification!")
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(fileContent)
	}))
	defer ts.Close()

	magURI := "magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=archlinux.iso&ws=" + ts.URL + "/archlinux.iso"
	info, err := ParseMagnetURI(magURI)
	if err != nil {
		t.Fatalf("ParseMagnetURI error: %v", err)
	}

	tc := NewTorrentClient()
	var dest bytes.Buffer
	var progressReported bool

	err = tc.DownloadTorrent(context.Background(), info, &dest, func(downloaded, total int64, speed string) {
		progressReported = true
	})
	if err != nil {
		t.Fatalf("DownloadTorrent failed: %v", err)
	}

	if dest.String() != string(fileContent) {
		t.Errorf("Downloaded payload mismatch: got %q", dest.String())
	}
	if !progressReported {
		t.Errorf("Expected progress callback to be called")
	}
}

func TestTorrentClient_AnnounceHTTPTracker(t *testing.T) {
	// Mock tracker responding with 1 peer (127.0.0.1:6881)
	peerIP := []byte{127, 0, 0, 1}
	var peerPort [2]byte
	binary.BigEndian.PutUint16(peerPort[:], 6881)
	compactPeers := append(peerIP, peerPort[:]...)

	trackerResp := map[string]interface{}{
		"interval": int64(1800),
		"peers":    string(compactPeers),
	}
	bencodedResp, err := MarshalBencode(trackerResp)
	if err != nil {
		t.Fatalf("Marshal tracker response failed: %v", err)
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bencodedResp)
	}))
	defer ts.Close()

	info, _ := ParseMagnetURI("magnet:?xt=urn:btih:da39a3ee5e6b4b0d3255bfef95601890afd80709&dn=test.iso&tr=" + ts.URL)
	tc := NewTorrentClient()

	peers, err := tc.announceHTTPTracker(context.Background(), ts.URL, info)
	if err != nil {
		t.Fatalf("announceHTTPTracker failed: %v", err)
	}

	if len(peers) != 1 || peers[0] != "127.0.0.1:6881" {
		t.Errorf("Expected peers ['127.0.0.1:6881'], got %v", peers)
	}
}

func TestTorrentClient_MockPeerDownload(t *testing.T) {
	// Start mock TCP peer
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	peerAddr := ln.Addr().String()

	infoHashHex := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	info, _ := ParseMagnetURI("magnet:?xt=urn:btih:" + infoHashHex + "&dn=sample.bin&xl=16")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read client handshake
		handshake := make([]byte, 68)
		_, _ = conn.Read(handshake)

		// Send peer handshake back
		respHandshake := make([]byte, 68)
		respHandshake[0] = 19
		copy(respHandshake[1:20], []byte("BitTorrent protocol"))
		copy(respHandshake[28:48], info.InfoHash[:])
		copy(respHandshake[48:68], []byte("-MOCK01-123456789012"))
		_, _ = conn.Write(respHandshake)

		time.Sleep(20 * time.Millisecond)

		// Send Unchoke (ID = 1, length = 1)
		unchoke := []byte{0, 0, 0, 1, 1}
		_, _ = conn.Write(unchoke)

		// Send Piece message (ID = 7, index = 0, begin = 0, data = "1234567890123456")
		payload := []byte("1234567890123456")
		msgLen := uint32(9 + len(payload))
		pieceMsg := make([]byte, 4+msgLen)
		binary.BigEndian.PutUint32(pieceMsg[0:4], msgLen)
		pieceMsg[4] = 7 // Piece ID
		binary.BigEndian.PutUint32(pieceMsg[5:9], 0) // index 0
		binary.BigEndian.PutUint32(pieceMsg[9:13], 0) // begin 0
		copy(pieceMsg[13:], payload)
		_, _ = conn.Write(pieceMsg)
	}()

	tc := NewTorrentClient()
	var dest bytes.Buffer

	err = tc.downloadFromPeer(context.Background(), peerAddr, info, &dest, nil)
	if err != nil {
		t.Fatalf("downloadFromPeer failed: %v", err)
	}

	if dest.String() != "1234567890123456" {
		t.Errorf("Expected '1234567890123456', got %q", dest.String())
	}
}

func TestTorrentClient_UnknownSizeMagnet_GracefulTermination(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	peerAddr := ln.Addr().String()
	// Magnet without xl parameter (BUG-SYS-18)
	infoHashHex := "da39a3ee5e6b4b0d3255bfef95601890afd80709"
	info, err := ParseMagnetURI("magnet:?xt=urn:btih:" + infoHashHex + "&dn=sample.bin")
	if err != nil {
		t.Fatalf("ParseMagnetURI failed: %v", err)
	}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		handshake := make([]byte, 68)
		_, _ = conn.Read(handshake)

		respHandshake := make([]byte, 68)
		respHandshake[0] = 19
		copy(respHandshake[1:20], []byte("BitTorrent protocol"))
		copy(respHandshake[28:48], info.InfoHash[:])
		copy(respHandshake[48:68], []byte("-MOCK01-123456789012"))
		_, _ = conn.Write(respHandshake)

		time.Sleep(20 * time.Millisecond)

		// Unchoke
		_, _ = conn.Write([]byte{0, 0, 0, 1, 1})

		// Read request
		reqBuf := make([]byte, 17)
		_, _ = conn.Read(reqBuf)

		// Send piece
		payload := []byte("streamed_chunk_without_known_length")
		msgLen := uint32(9 + len(payload))
		pieceMsg := make([]byte, 4+msgLen)
		binary.BigEndian.PutUint32(pieceMsg[0:4], msgLen)
		pieceMsg[4] = 7
		binary.BigEndian.PutUint32(pieceMsg[5:9], 0)
		binary.BigEndian.PutUint32(pieceMsg[9:13], 0)
		copy(pieceMsg[13:], payload)
		_, _ = conn.Write(pieceMsg)

		// Send Keep-Alive (length = 0) and close
		time.Sleep(50 * time.Millisecond)
		_, _ = conn.Write([]byte{0, 0, 0, 0})
	}()

	tc := NewTorrentClient()
	var dest bytes.Buffer

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = tc.downloadFromPeer(ctx, peerAddr, info, &dest, nil)
	if err != nil {
		t.Fatalf("downloadFromPeer failed on unknown size magnet: %v", err)
	}

	if dest.String() != "streamed_chunk_without_known_length" {
		t.Errorf("Expected 'streamed_chunk_without_known_length', got %q", dest.String())
	}
}
