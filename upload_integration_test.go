package ztatic

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ztatic-go-framework/upload"
)

var sampleValidPNG = []byte{
	0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
	0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
	0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
	0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
	0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
}

type avatarFormRequest struct {
	UserID string                `form:"user_id" validate:"required"`
	Avatar *multipart.FileHeader `form:"avatar" validate:"required,file_max=5MB,file_ext=.png;.jpg,file_mime=image/png;image/jpeg"`
}

func TestUploadIntegration_EndToEnd_SecureEngine(t *testing.T) {
	app := NewSecure()
	memStore := NewMemoryStorage()
	heurScanner := NewHeuristicScanner()

	uploader, err := NewUploader(UploadConfig{
		MaxFileSize:       5 * upload.MB,
		AllowedMIMEs:      upload.ImageMIMEs(),
		AllowedExtensions: upload.ImageExtensions(),
		NamingStrategy:    upload.StrategyUUID,
		Scanner:           heurScanner,
		Storage:           memStore,
	})
	if err != nil {
		t.Fatalf("failed to create uploader: %v", err)
	}

	// 1. Mount upload endpoint with RouteLimit and AutoCleanup
	app.POST("/api/upload/avatar", func(c *Context) error {
		var req avatarFormRequest
		if err := BindAndValidate(c, &req); err != nil {
			return err
		}

		processed, err := uploader.ProcessFileHeader(c.Request().Context(), req.Avatar)
		if err != nil {
			return err
		}

		return OK(c, Map{
			"key":           processed.Key,
			"original_name": processed.OriginalName,
			"mime":          processed.MIME,
			"size":          processed.Size,
			"user_id":       req.UserID,
		})
	}, UploadRouteLimit(10*upload.MB), UploadAutoCleanup())

	// 2. Mount safe file serving endpoint
	app.GET("/api/files/:key", func(c *Context) error {
		key := c.Param("key")
		return ServeFile(c, memStore, key, upload.WithInline())
	})

	// 3. Perform valid multipart upload through the secure engine pipeline
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	_ = writer.WriteField("user_id", "usr_12345")
	part, err := writer.CreateFormFile("avatar", "profile.png")
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	_, _ = part.Write(sampleValidPNG)
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, "/api/upload/avatar", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d. Response: %s", rec.Code, rec.Body.String())
	}

	if !strings.Contains(rec.Body.String(), `"user_id":"usr_12345"`) {
		t.Errorf("expected response to contain user_id, got: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"mime":"image/png"`) {
		t.Errorf("expected response to contain image/png, got: %s", rec.Body.String())
	}

	// 4. Test malware interception in the pipeline
	maliciousSVG := []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert('pwned')</script></svg>`)
	badBody := &bytes.Buffer{}
	badWriter := multipart.NewWriter(badBody)
	_ = badWriter.WriteField("user_id", "usr_hacker")
	badPart, _ := badWriter.CreateFormFile("avatar", "exploit.png") // disguised SVG/script
	_, _ = badPart.Write(maliciousSVG)
	_ = badWriter.Close()

	badReq := httptest.NewRequest(http.MethodPost, "/api/upload/avatar", badBody)
	badReq.Header.Set("Content-Type", badWriter.FormDataContentType())
	badRec := httptest.NewRecorder()
	app.ServeHTTP(badRec, badReq)

	// Disguised script inside .png should fail validation / MIME mismatch
	if badRec.Code == http.StatusOK {
		t.Errorf("expected malicious file to be rejected, got HTTP 200")
	}
}
