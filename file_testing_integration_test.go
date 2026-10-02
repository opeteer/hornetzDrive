package ztatic_test

import (
	"context"
	"mime/multipart"
	"net/http"
	"testing"

	"ztatic-go-framework"
	"ztatic-go-framework/fileassert"
	"ztatic-go-framework/filetest"
	"ztatic-go-framework/upload"
	"ztatic-go-framework/upload/storage"
)

type userProfileUploadForm struct {
	UserID string                `form:"user_id" validate:"required"`
	Bio    string                `form:"bio"`
	Avatar *multipart.FileHeader `form:"avatar" validate:"required,file_max=5MB,file_ext=.png;.jpg;.jpeg,file_mime=image/png;image/jpeg"`
}

func TestFileTestingIntegration_FullLifecycle(t *testing.T) {
	app := ztatic.NewSecure()
	mockStore := filetest.NewMockStorage()
	mockScan := filetest.NewMockScanner()

	uploader, err := ztatic.NewUploader(ztatic.UploadConfig{
		MaxFileSize:       5 * upload.MB,
		AllowedMIMEs:      upload.ImageMIMEs(),
		AllowedExtensions: upload.ImageExtensions(),
		NamingStrategy:    upload.StrategyUUID,
		Scanner:           mockScan,
		Storage:           mockStore,
	})
	if err != nil {
		t.Fatalf("failed to create uploader: %v", err)
	}

	// 1. Mount Upload Endpoint with validation and route-level limit
	app.POST("/api/users/avatar", func(c *ztatic.Context) error {
		var form userProfileUploadForm
		if err := ztatic.BindAndValidate(c, &form); err != nil {
			return err
		}

		processed, err := uploader.ProcessFileHeader(c.Request().Context(), form.Avatar)
		if err != nil {
			return err
		}

		return ztatic.OK(c, ztatic.Map{
			"user_id":       form.UserID,
			"bio":           form.Bio,
			"key":           processed.Key,
			"original_name": processed.OriginalName,
			"size":          processed.Size,
			"mime":          processed.MIME,
			"url":           processed.URL,
		})
	}, ztatic.UploadRouteLimit(10*upload.MB), ztatic.UploadAutoCleanup())

	// 2. Mount Safe File Serving Endpoint
	app.GET("/api/files/:key", func(c *ztatic.Context) error {
		key := c.Param("key")
		return ztatic.ServeFile(c, mockStore, key, upload.WithInline())
	})

	client := app.TestClient()

	// -------------------------------------------------------------------------
	// Scenario A: Successful Valid Upload
	// -------------------------------------------------------------------------
	avatarFixture := filetest.PNG("user_avatar.png", 150, 150)

	uploadResp := client.NewUpload("/api/users/avatar").
		Field("user_id", "usr_9988").
		Field("bio", "Software engineer & open-source builder").
		Attach("avatar", avatarFixture).
		WithBearerToken("auth-jwt-token-xyz").
		Send()

	uploadResp.AssertOK(t).
		AssertContentType(t, "application/json").
		AssertBodyContains(t, `"user_id":"usr_9988"`).
		AssertBodyContains(t, `"original_name":"user_avatar.png"`).
		AssertBodyContains(t, `"mime":"image/png"`)

	// Parse response payload to retrieve generated storage key
	var env struct {
		Success bool `json:"success"`
		Data    struct {
			Key string `json:"key"`
		} `json:"data"`
	}
	if err := uploadResp.JSON(&env); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}
	savedKey := env.Data.Key
	if savedKey == "" {
		t.Fatalf("expected non-empty storage key in response")
	}

	// Verify Storage and Scanner spies
	fileassert.Exists(t, mockStore, savedKey)
	fileassert.Saved(t, mockStore, savedKey)
	fileassert.SavedCount(t, mockStore, 1)
	fileassert.Size(t, mockStore, savedKey, avatarFixture.Size())
	fileassert.ContentEquals(t, mockStore, savedKey, avatarFixture.Bytes())
	fileassert.Scanned(t, mockScan, "user_avatar.png")
	fileassert.ScanCount(t, mockScan, 1)

	// -------------------------------------------------------------------------
	// Scenario B: File Retrieval & Range Streaming
	// -------------------------------------------------------------------------
	dlResp := client.NewDownload("/api/files/" + savedKey).Send()
	dlResp.AssertOK(t).
		AssertInline(t, "user_avatar.png").
		AssertContentType(t, "image/png").
		AssertNoSniff(t).
		AssertAcceptRanges(t).
		AssertContentLength(t, avatarFixture.Size()).
		AssertContentEquals(t, avatarFixture.Bytes())

	// HTTP 206 Partial Content Range streaming
	rangeResp := client.NewDownload("/api/files/" + savedKey).
		WithRange(0, 49).
		Send()
	rangeResp.AssertPartialContent(t, 0, 49, avatarFixture.Size()).
		AssertContentLength(t, 50).
		AssertContentEquals(t, avatarFixture.Bytes()[:50])

	// -------------------------------------------------------------------------
	// Scenario C: Security Rejection (Disguised Executable)
	// -------------------------------------------------------------------------
	disguisedPE := filetest.DisguisedExecutable("trojan.png", filetest.ExecutablePE)

	badResp := client.NewUpload("/api/users/avatar").
		Field("user_id", "usr_hacker").
		Attach("avatar", disguisedPE).
		Send()

	// Should be rejected by MIME sniffing / anti-spoofing validation
	if badResp.StatusCode == http.StatusOK {
		t.Errorf("expected disguised executable to be rejected, got HTTP 200")
	}
	fileassert.NotSaved(t, mockStore, "trojan.png")

	// -------------------------------------------------------------------------
	// Scenario D: Malware Scanner Flagging & Audit Blocking
	// -------------------------------------------------------------------------
	mockScan.FlagFilename("infected", "Trojan.Agent.Mock")

	infectedFixture := filetest.PNG("infected_avatar.png", 64, 64)
	infectedResp := client.NewUpload("/api/users/avatar").
		Field("user_id", "usr_victim").
		Attach("avatar", infectedFixture).
		Send()

	infectedResp.AssertForbidden(t).
		AssertBodyContains(t, "MALWARE_DETECTED")

	// -------------------------------------------------------------------------
	// Scenario E: Storage Fault Injection (Disk Full)
	// -------------------------------------------------------------------------
	mockScan.AlwaysClean()
	mockStore.SimulateDiskFull()

	diskFullFixture := filetest.PNG("clean_pic.png", 64, 64)
	diskFullResp := client.NewUpload("/api/users/avatar").
		Field("user_id", "usr_normal").
		Attach("avatar", diskFullFixture).
		Send()

	// Storage failure should yield HTTP 500 internal server error
	diskFullResp.AssertStatus(t, http.StatusInternalServerError)
}

func TestFileTestingIntegration_LocalStorageAndTempSandbox(t *testing.T) {
	// Demonstrates integration with real disk-backed LocalStorage utilizing TempSandbox
	sandbox := filetest.TempSandbox(t)
	localStorage, err := ztatic.NewLocalStorage(sandbox.Dir)
	if err != nil {
		t.Fatalf("failed to initialize LocalStorage: %v", err)
	}

	app := ztatic.New()
	app.GET("/download/:key", func(c *ztatic.Context) error {
		key := c.Param("key")
		return ztatic.ServeFile(c, localStorage, key, upload.WithDownload())
	})

	// Seed file into the sandbox directory through LocalStorage
	pdfFix := filetest.PDF("handbook.pdf", "Corporate Security Policy")
	record, err := localStorage.Save(cCtx(), "handbook.pdf", pdfFix.Reader(), pdfFix.Size(), storage.SaveOptions{
		OriginalName: "handbook.pdf",
		MIME:         pdfFix.MIME(),
	})
	if err != nil {
		t.Fatalf("LocalStorage Save failed: %v", err)
	}

	client := app.TestClient()
	resp := client.Get("/download/" + record.Key)

	resp.AssertOK(t).
		AssertDownloaded(t, "handbook.pdf").
		AssertContentType(t, "application/pdf").
		AssertContentEquals(t, pdfFix.Bytes())
}

func cCtx() context.Context {
	return context.Background()
}
