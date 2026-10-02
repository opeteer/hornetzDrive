package scanner

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// ClamAVConfig defines configuration for connecting to clamd daemon.
type ClamAVConfig struct {
	// Network is "tcp" or "unix" (default: "tcp").
	Network string
	// Address is "host:port" for TCP or file path for Unix socket (default: "127.0.0.1:3310").
	Address string
	// Timeout specifies connection and read/write timeouts (default: 10s).
	Timeout time.Duration
	// ChunkSize defines stream chunk size sent to INSTREAM (default: 32KB).
	ChunkSize int
}

// DefaultClamAVConfig returns standard localhost clamd settings.
func DefaultClamAVConfig() ClamAVConfig {
	return ClamAVConfig{
		Network:   "tcp",
		Address:   "127.0.0.1:3310",
		Timeout:   10 * time.Second,
		ChunkSize: 32 * 1024,
	}
}

// ClamAVScanner inspects files by streaming chunks to ClamAV daemon via INSTREAM protocol.
type ClamAVScanner struct {
	cfg ClamAVConfig
}

// NewClamAVScanner creates a ClamAV scanner with the given address (tcp or unix).
func NewClamAVScanner(address string) *ClamAVScanner {
	cfg := DefaultClamAVConfig()
	if address != "" {
		if strings.HasPrefix(address, "/") {
			cfg.Network = "unix"
		}
		cfg.Address = address
	}
	return NewClamAVScannerWithConfig(cfg)
}

// NewClamAVScannerWithConfig creates a ClamAV scanner with full configuration.
func NewClamAVScannerWithConfig(cfg ClamAVConfig) *ClamAVScanner {
	if cfg.Network == "" {
		cfg.Network = "tcp"
	}
	if cfg.Address == "" {
		cfg.Address = "127.0.0.1:3310"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = 32 * 1024
	}
	return &ClamAVScanner{cfg: cfg}
}

// Ping verifies connectivity to the ClamAV daemon.
func (s *ClamAVScanner) Ping(ctx context.Context) error {
	conn, err := s.dial(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()

	if s.cfg.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	}

	if _, err := conn.Write([]byte("zPING\x00")); err != nil {
		return fmt.Errorf("clamav ping write error: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\x00')
	if err != nil && err != io.EOF {
		return fmt.Errorf("clamav ping read error: %w", err)
	}

	resp = strings.TrimRight(resp, "\x00\r\n")
	if resp != "PONG" {
		return fmt.Errorf("unexpected ping response: %q", resp)
	}

	return nil
}

// Scan streams the file to clamd using INSTREAM protocol.
func (s *ClamAVScanner) Scan(ctx context.Context, r io.ReaderAt, size int64, info FileInfo) (*ScanResult, error) {
	conn, err := s.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("clamav connection failed: %w", err)
	}
	defer conn.Close()

	if s.cfg.Timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	}

	// 1. Send INSTREAM command with null delimiter
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("clamav instream command failed: %w", err)
	}

	// 2. Stream chunks: 4-byte big-endian length + chunk data
	buf := make([]byte, s.cfg.ChunkSize)
	lenBuf := make([]byte, 4)
	var offset int64

	for offset < size {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		toRead := int64(len(buf))
		if size-offset < toRead {
			toRead = size - offset
		}

		n, err := r.ReadAt(buf[:toRead], offset)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				return nil, fmt.Errorf("clamav chunk length write error: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return nil, fmt.Errorf("clamav chunk data write error: %w", err)
			}
			offset += int64(n)
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
	}

	// 3. Terminate stream with zero length chunk (4 null bytes)
	binary.BigEndian.PutUint32(lenBuf, 0)
	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("clamav stream terminator write error: %w", err)
	}

	// 4. Read response
	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\x00')
	if err != nil && err != io.EOF {
		// Fallback for line-terminated response
		resp, err = reader.ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("clamav response read error: %w", err)
		}
	}

	resp = strings.TrimRight(resp, "\x00\r\n")

	// Responses typically format as:
	// "stream: OK"
	// "stream: Win.Trojan.Agent-12345 FOUND"
	if strings.HasSuffix(resp, "OK") {
		return &ScanResult{
			Clean:       true,
			ScannerName: "ClamAV",
		}, nil
	}

	if strings.HasSuffix(resp, "FOUND") {
		// Extract threat name
		threat := strings.TrimPrefix(resp, "stream: ")
		threat = strings.TrimSuffix(threat, " FOUND")
		return &ScanResult{
			Clean:       false,
			ThreatName:  threat,
			ScannerName: "ClamAV",
			Details: map[string]any{
				"raw_response": resp,
			},
		}, nil
	}

	return nil, fmt.Errorf("clamav scan error: %s", resp)
}

func (s *ClamAVScanner) dial(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	d.Timeout = s.cfg.Timeout
	return d.DialContext(ctx, s.cfg.Network, s.cfg.Address)
}
