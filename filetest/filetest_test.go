package filetest_test

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"image"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/fileassert"
	"ztatic-go-framework/filetest"
	"ztatic-go-framework/upload"
	"ztatic-go-framework/upload/scanner"
	"ztatic-go-framework/upload/storage"
)

// -----------------------------------------------------------------------------
// 1. Fixtures Tests
// -----------------------------------------------------------------------------

func TestFixtures_Images(t *testing.T) {
	// PNG
	pngFix := filetest.PNG("avatar.png", 64, 48)
	if pngFix.Name() != "avatar.png" || pngFix.MIME() != "image/png" {
		t.Fatalf("unexpected PNG fixture attributes: %s, %s", pngFix.Name(), pngFix.MIME())
	}
	pngCfg, pngFormat, err := image.DecodeConfig(pngFix.Reader())
	if err != nil || pngFormat != "png" || pngCfg.Width != 64 || pngCfg.Height != 48 {
		t.Errorf("PNG config decoding failed or mismatch: format=%s, %dx%d, err=%v", pngFormat, pngCfg.Width, pngCfg.Height, err)
	}

	// JPEG
	jpegFix := filetest.JPEG("photo.jpg", 100, 80)
	if jpegFix.Name() != "photo.jpg" || jpegFix.MIME() != "image/jpeg" {
		t.Fatalf("unexpected JPEG fixture attributes: %s, %s", jpegFix.Name(), jpegFix.MIME())
	}
	jpgCfg, jpgFormat, err := image.DecodeConfig(jpegFix.Reader())
	if err != nil || jpgFormat != "jpeg" || jpgCfg.Width != 100 || jpgCfg.Height != 80 {
		t.Errorf("JPEG config decoding failed or mismatch: format=%s, %dx%d, err=%v", jpgFormat, jpgCfg.Width, jpgCfg.Height, err)
	}

	// GIF
	gifFix := filetest.GIF("animation.gif", 32, 32)
	if gifFix.Name() != "animation.gif" || gifFix.MIME() != "image/gif" {
		t.Fatalf("unexpected GIF fixture attributes: %s, %s", gifFix.Name(), gifFix.MIME())
	}
	gifCfg, gifFormat, err := image.DecodeConfig(gifFix.Reader())
	if err != nil || gifFormat != "gif" || gifCfg.Width != 32 || gifCfg.Height != 32 {
		t.Errorf("GIF config decoding failed or mismatch: format=%s, %dx%d, err=%v", gifFormat, gifCfg.Width, gifCfg.Height, err)
	}

	// WebP
	webpFix := filetest.WebP("card.webp")
	if webFixName := webpFix.Name(); webFixName != "card.webp" || webpFix.MIME() != "image/webp" {
		t.Errorf("unexpected WebP attributes: %s, %s", webFixName, webpFix.MIME())
	}
	if !bytes.HasPrefix(webpFix.Bytes(), []byte("RIFF")) {
		t.Errorf("expected WebP to start with RIFF header")
	}

	// SVG
	svgFix := filetest.SVG("logo.svg", 120, 60, `<text>Ztatic</text>`)
	if svgFix.Name() != "logo.svg" || svgFix.MIME() != "image/svg+xml" {
		t.Errorf("unexpected SVG attributes")
	}
	if !strings.Contains(string(svgFix.Bytes()), `<text>Ztatic</text>`) {
		t.Errorf("expected SVG to contain inner text")
	}
}

func TestFixtures_DocumentsAndData(t *testing.T) {
	// PDF
	pdfFix := filetest.PDF("manual.pdf", "Hello Ztatic Framework")
	if pdfFix.MIME() != "application/pdf" {
		t.Errorf("expected application/pdf, got %s", pdfFix.MIME())
	}
	if !strings.HasPrefix(string(pdfFix.Bytes()), "%PDF-1.4") {
		t.Errorf("expected PDF magic header %%PDF-1.4")
	}

	// Text
	txtFix := filetest.Text("notes.txt", "line1\nline2")
	if txtFix.MIME() != "text/plain" || string(txtFix.Bytes()) != "line1\nline2" {
		t.Errorf("unexpected Text fixture")
	}

	// CSV
	csvFix := filetest.CSV("users.csv", [][]string{
		{"id", "name"},
		{"1", "Alice"},
	})
	if csvFix.MIME() != "text/csv" || !strings.Contains(string(csvFix.Bytes()), "Alice") {
		t.Errorf("unexpected CSV fixture")
	}

	// JSON
	jsonFix := filetest.JSON("payload.json", map[string]any{"ok": true, "code": 200})
	if jsonFix.MIME() != "application/json" || !strings.Contains(string(jsonFix.Bytes()), `"ok": true`) {
		t.Errorf("unexpected JSON fixture")
	}
}

func TestFixtures_SecurityAndAdversarial(t *testing.T) {
	// Malicious SVG: Script tag
	malSVG := filetest.MaliciousSVG("xss.svg", filetest.SVGAttackScriptTag)
	if !strings.Contains(string(malSVG.Bytes()), "<script>alert('xss')</script>") {
		t.Errorf("expected script tag in malicious SVG")
	}

	// Malicious SVG: Event handler
	evtSVG := filetest.MaliciousSVG("onload.svg", filetest.SVGAttackEventHandler)
	if !strings.Contains(string(evtSVG.Bytes()), "onload=") {
		t.Errorf("expected onload handler in malicious SVG")
	}

	// Malicious SVG: Javascript URI
	jsSVG := filetest.MaliciousSVG("link.svg", filetest.SVGAttackJavascriptURI)
	if !strings.Contains(string(jsSVG.Bytes()), "javascript:") {
		t.Errorf("expected javascript: link in malicious SVG")
	}

	// Malicious SVG: XXE
	xxeSVG := filetest.MaliciousSVG("xxe.svg", filetest.SVGAttackXXE)
	if !strings.Contains(string(xxeSVG.Bytes()), "<!ENTITY") {
		t.Errorf("expected <!ENTITY in malicious SVG")
	}

	// WebShell
	phpShell := filetest.WebShell("shell.php", filetest.WebShellPHP)
	if !strings.Contains(string(phpShell.Bytes()), "<?php system") {
		t.Errorf("expected <?php in webshell fixture")
	}

	// Executables
	peExe := filetest.Executable("app.exe", filetest.ExecutablePE)
	if !bytes.HasPrefix(peExe.Bytes(), []byte{0x4D, 0x5A}) {
		t.Errorf("expected MZ PE header")
	}

	elfExe := filetest.Executable("binary", filetest.ExecutableELF)
	if !bytes.HasPrefix(elfExe.Bytes(), []byte{0x7F, 'E', 'L', 'F'}) {
		t.Errorf("expected ELF header")
	}

	machoExe := filetest.Executable("macho", filetest.ExecutableMachO)
	if !bytes.HasPrefix(machoExe.Bytes(), []byte{0xFE, 0xED, 0xFA, 0xCF}) {
		t.Errorf("expected Mach-O header")
	}

	// Disguised Executable
	disguised := filetest.DisguisedExecutable("innocent.png", filetest.ExecutablePE)
	if disguised.Name() != "innocent.png" || !bytes.HasPrefix(disguised.Bytes(), []byte{0x4D, 0x5A}) {
		t.Errorf("disguised executable should retain .png extension with PE bytes")
	}

	// ZipSlip
	zipSlip := filetest.ZipSlip("slip.zip", "../../etc/passwd", []byte("root:x:0:0"))
	zr, err := zip.NewReader(zipSlip.ReaderAt(), zipSlip.Size())
	if err != nil || len(zr.File) != 1 || zr.File[0].Name != "../../etc/passwd" {
		t.Errorf("ZipSlip archive verification failed: %v", err)
	}

	// ZipBomb
	zipBomb := filetest.ZipBomb("bomb.zip", 1) // 1 MB
	if zipBomb.Size() <= 0 {
		t.Errorf("expected non-zero zip bomb size")
	}
}

func TestFixtures_VolumeAndEdgeCases(t *testing.T) {
	// Oversized virtual reader
	virtualSize := int64(50 * 1024 * 1024) // 50 MB
	overFix := filetest.Oversized("huge.iso", virtualSize)
	if overFix.Size() != virtualSize {
		t.Errorf("expected size %d, got %d", virtualSize, overFix.Size())
	}

	// Stream small chunk
	buf := make([]byte, 1024)
	n, err := overFix.Reader().Read(buf)
	if err != nil || n != 1024 {
		t.Errorf("failed to stream from oversized fixture: n=%d, err=%v", n, err)
	}

	// ReadAt chunk
	atBuf := make([]byte, 2048)
	nAt, err := overFix.ReaderAt().ReadAt(atBuf, 1000)
	if err != nil || nAt != 2048 {
		t.Errorf("failed to ReadAt from oversized fixture: n=%d, err=%v", nAt, err)
	}

	// Truncated
	baseFix := filetest.Text("base.txt", "1234567890")
	truncFix := filetest.Truncated(baseFix, 4)
	if string(truncFix.Bytes()) != "1234" {
		t.Errorf("expected truncated '1234', got %q", string(truncFix.Bytes()))
	}

	// Empty
	emptyFix := filetest.Empty("empty.dat")
	if emptyFix.Size() != 0 || len(emptyFix.Bytes()) != 0 {
		t.Errorf("expected 0 byte empty fixture")
	}
}

func TestFixtures_TempSandbox(t *testing.T) {
	sandbox := filetest.TempSandbox(t)
	if sandbox.Dir == "" {
		t.Fatalf("expected non-empty sandbox dir")
	}

	p := sandbox.WriteFile("docs/test.txt", []byte("sandbox content"))
	if !sandbox.Exists("docs/test.txt") {
		t.Errorf("expected written file to exist in sandbox")
	}
	if string(sandbox.ReadFile("docs/test.txt")) != "sandbox content" {
		t.Errorf("sandbox content mismatch")
	}
	if !strings.HasSuffix(p, "docs/test.txt") {
		t.Errorf("unexpected full path: %s", p)
	}

	sub := sandbox.Subdir("storage/cache")
	if !strings.HasSuffix(sub, "storage/cache") {
		t.Errorf("unexpected subdir path: %s", sub)
	}
}

// -----------------------------------------------------------------------------
// 2. MockStorage Tests
// -----------------------------------------------------------------------------

func TestMockStorage_OperationsAndSpies(t *testing.T) {
	store := filetest.NewMockStorage()
	ctx := context.Background()

	// 1. Initial State
	fileassert.Missing(t, store, "file1.png")
	fileassert.FileCount(t, store, 0)

	// 2. Save
	rec, err := store.Save(ctx, "file1.png", bytes.NewReader([]byte("png-payload")), 11, storage.SaveOptions{
		OriginalName: "avatar.png",
		MIME:         "image/png",
		Extension:    ".png",
		SHA256:       "mock-sha",
	})
	if err != nil {
		t.Fatalf("Save failed: %v", err)
	}
	if rec.Key != "file1.png" || rec.Size != 11 {
		t.Errorf("unexpected record from Save: %+v", rec)
	}

	// Assertions & Spies
	fileassert.Exists(t, store, "file1.png")
	fileassert.Saved(t, store, "file1.png")
	fileassert.NotSaved(t, store, "file2.png")
	fileassert.SavedCount(t, store, 1)
	fileassert.FileCount(t, store, 1)
	fileassert.ContentEquals(t, store, "file1.png", []byte("png-payload"))
	fileassert.ContentString(t, store, "file1.png", "png-payload")
	fileassert.Size(t, store, "file1.png", 11)
	fileassert.MIME(t, store, "file1.png", "image/png")
	fileassert.SHA256(t, store, "file1.png", "mock-sha")

	lastCall := store.LastSaveCall()
	if lastCall == nil || lastCall.Key != "file1.png" || string(lastCall.Content) != "png-payload" {
		t.Errorf("LastSaveCall mismatch: %+v", lastCall)
	}

	// 3. Open
	reader, openRec, err := store.Open(ctx, "file1.png")
	if err != nil || openRec.Key != "file1.png" {
		t.Fatalf("Open failed: %v", err)
	}
	defer reader.Close()
	if !store.WasOpened("file1.png") {
		t.Errorf("expected WasOpened to be true")
	}

	// 4. URL
	url, err := store.URL(ctx, "file1.png", storage.URLOptions{Filename: "avatar.png"})
	if err != nil || url != "/files/file1.png" {
		t.Errorf("URL generation mismatch: %s, %v", url, err)
	}

	// 5. Delete
	err = store.Delete(ctx, "file1.png")
	if err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	fileassert.Deleted(t, store, "file1.png")
	fileassert.DeletedCount(t, store, 1)
	fileassert.Missing(t, store, "file1.png")
}

func TestMockStorage_FaultInjection(t *testing.T) {
	store := filetest.NewMockStorage()
	ctx := context.Background()

	// 1. Simulate Disk Full
	store.SimulateDiskFull()
	_, err := store.Save(ctx, "k1", strings.NewReader("data"), 4, storage.SaveOptions{})
	if err == nil || !strings.Contains(err.Error(), "no space left on device") {
		t.Errorf("expected disk full error, got: %v", err)
	}

	// Reset
	store.Reset()
	_, err = store.Save(ctx, "k1", strings.NewReader("data"), 4, storage.SaveOptions{})
	if err != nil {
		t.Fatalf("expected Save to succeed after reset, got: %v", err)
	}

	// 2. Fail Save For Specific Key
	store.FailSaveForKey("bad.txt", errors.New("key denied"))
	_, err = store.Save(ctx, "good.txt", strings.NewReader("ok"), 2, storage.SaveOptions{})
	if err != nil {
		t.Errorf("good.txt should not have failed: %v", err)
	}
	_, err = store.Save(ctx, "bad.txt", strings.NewReader("fail"), 4, storage.SaveOptions{})
	if err == nil || err.Error() != "key denied" {
		t.Errorf("bad.txt should have failed with 'key denied', got: %v", err)
	}

	// 3. Fail Open
	store.FailOpen(errors.New("open error"))
	_, _, err = store.Open(ctx, "k1")
	if err == nil || err.Error() != "open error" {
		t.Errorf("expected open error, got: %v", err)
	}

	// 4. Fail Delete
	store.FailDelete(errors.New("delete error"))
	err = store.Delete(ctx, "k1")
	if err == nil || err.Error() != "delete error" {
		t.Errorf("expected delete error, got: %v", err)
	}

	// 5. Seed File
	store.Reset()
	store.SeedFile("pre-existing.csv", []byte("a,b,c"), "text/csv")
	fileassert.Exists(t, store, "pre-existing.csv")
	fileassert.ContentString(t, store, "pre-existing.csv", "a,b,c")
}

// -----------------------------------------------------------------------------
// 3. MockScanner Tests
// -----------------------------------------------------------------------------

func TestMockScanner_RulesAndSpies(t *testing.T) {
	scan := filetest.NewMockScanner()
	ctx := context.Background()

	// 1. Default clean scan
	res, err := scan.Scan(ctx, strings.NewReader("ok"), 2, scanner.FileInfo{Filename: "clean.png"})
	if err != nil {
		t.Fatalf("unexpected scan error: %v", err)
	}
	fileassert.ScanClean(t, res)
	fileassert.Scanned(t, scan, "clean.png")
	fileassert.NotScanned(t, scan, "other.png")
	fileassert.ScanCount(t, scan, 1)

	// 2. Flag Threat Unconditionally
	scan.FlagThreat("Trojan.Mock.Generic")
	res, _ = scan.Scan(ctx, strings.NewReader("bad"), 3, scanner.FileInfo{Filename: "test.jpg"})
	fileassert.ScanInfected(t, res, "Trojan.Mock.Generic")

	// 3. Flag by Filename Pattern
	scan.AlwaysClean()
	scan.FlagFilename("virus", "Virus.TestPattern")
	resClean, _ := scan.Scan(ctx, strings.NewReader("x"), 1, scanner.FileInfo{Filename: "safe.pdf"})
	fileassert.ScanClean(t, resClean)

	resVirus, _ := scan.Scan(ctx, strings.NewReader("x"), 1, scanner.FileInfo{Filename: "my_virus_payload.doc"})
	fileassert.ScanInfected(t, resVirus, "Virus.TestPattern")

	// 4. Fail With Error (for testing FailClosed policy)
	customErr := errors.New("clamd connection refused")
	scan.FailWithError(customErr)
	_, err = scan.Scan(ctx, strings.NewReader("x"), 1, scanner.FileInfo{Filename: "any.dat"})
	if !errors.Is(err, customErr) {
		t.Errorf("expected scanner fail error, got: %v", err)
	}

	// 5. Simulate Timeout
	scan.SimulateTimeout()
	_, err = scan.Scan(ctx, strings.NewReader("x"), 1, scanner.FileInfo{Filename: "any.dat"})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected context.DeadlineExceeded, got: %v", err)
	}
}

// -----------------------------------------------------------------------------
// 4. Client & Fluent Response Assertions
// -----------------------------------------------------------------------------

func TestClient_UploadAndDownloadEndToEnd(t *testing.T) {
	e := echo.New()

	// Test upload route
	e.POST("/upload", func(c *echo.Context) error {
		tag := c.FormValue("tag")
		fh, err := c.FormFile("attachment")
		if err != nil {
			return c.String(http.StatusBadRequest, err.Error())
		}
		authHeader := c.Request().Header.Get("Authorization")
		cookie, _ := c.Cookie("test_sess")

		sessVal := ""
		if cookie != nil {
			sessVal = cookie.Value
		}

		return c.JSON(http.StatusOK, map[string]any{
			"filename": fh.Filename,
			"tag":      tag,
			"size":     fh.Size,
			"auth":     authHeader,
			"sess":     sessVal,
		})
	})

	// Test file serving download route with Range and headers
	mockData := []byte("0123456789abcdefghijklmnopqrstuvwxyz")
	e.GET("/download/:name", func(c *echo.Context) error {
		name := c.Param("name")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		c.Response().Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
		c.Response().Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
		c.Response().Header().Set("ETag", `"mock-etag-123"`)
		http.ServeContent(c.Response(), c.Request(), name, time.Now().UTC(), bytes.NewReader(mockData))
		return nil
	})

	client := filetest.NewClient(e)

	// 1. Multipart Upload with Attach, Fields, BearerToken, Cookie
	sessCookie := &http.Cookie{Name: "test_sess", Value: "sess_xyz"}
	fixtureFile := filetest.Text("report.txt", "Report content line 1")

	resp := client.NewUpload("/upload").
		Field("tag", "finance").
		Attach("attachment", fixtureFile).
		WithBearerToken("jwt_token_sample").
		WithCookie(sessCookie).
		Send()

	// Response assertions
	resp.AssertOK(t).
		AssertContentType(t, "application/json").
		AssertBodyContains(t, `"tag":"finance"`).
		AssertBodyContains(t, `"filename":"report.txt"`).
		AssertBodyContains(t, `"auth":"Bearer jwt_token_sample"`).
		AssertBodyContains(t, `"sess":"sess_xyz"`)

	// 2. Download Request & Assertions
	dlResp := client.NewDownload("/download/statement.pdf").
		Send()

	dlResp.AssertOK(t).
		AssertDownloaded(t, "statement.pdf").
		AssertNoSniff(t).
		AssertSandboxedCSP(t).
		AssertAcceptRanges(t).
		AssertContentEquals(t, mockData)

	if dlResp.ETag() != "mock-etag-123" {
		t.Errorf("expected ETag mock-etag-123, got %q", dlResp.ETag())
	}
	if dlResp.Filename() != "statement.pdf" {
		t.Errorf("expected filename statement.pdf, got %q", dlResp.Filename())
	}

	// 2b. Conditional GET with matching ETag returns 304 Not Modified
	cacheResp := client.NewDownload("/download/statement.pdf").
		WithETag("mock-etag-123").
		Send()
	cacheResp.AssertStatus(t, http.StatusNotModified)

	// 3. HTTP 206 Partial Content Range Request
	rangeResp := client.NewDownload("/download/statement.pdf").
		WithRange(0, 9).
		Send()

	rangeResp.AssertPartialContent(t, 0, 9, int64(len(mockData))).
		AssertContentLength(t, 10).
		AssertContentEquals(t, mockData[:10])
}

// -----------------------------------------------------------------------------
// 5. Harness & TestManager
// -----------------------------------------------------------------------------

func TestHarness_And_TestManager(t *testing.T) {
	mgr, store, scanner := filetest.NewTestManager(func(cfg *upload.Config) {
		cfg.MaxFileSize = 5 * upload.MB
	})

	if mgr == nil || store == nil || scanner == nil {
		t.Fatalf("expected non-nil manager, store, and scanner from NewTestManager")
	}

	// Test processing with test manager
	fix := filetest.PNG("test_avatar.png", 50, 50)
	processed, err := mgr.ProcessReader(context.Background(), fix.ReaderAt(), fix.Size(), fix.Name())
	if err != nil {
		t.Fatalf("ProcessReader failed: %v", err)
	}

	if processed.OriginalName != "test_avatar.png" || processed.MIME != "image/png" {
		t.Errorf("unexpected processed metadata: %+v", processed)
	}

	// Verify spies
	fileassert.Saved(t, store, processed.Key)
	fileassert.Scanned(t, scanner, "test_avatar.png")
	fileassert.SavedCount(t, store, 1)
	fileassert.ScanCount(t, scanner, 1)
}
