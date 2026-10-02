package validation

import (
	"bytes"
	"context"
	"mime/multipart"
	"testing"
)

type rulesSample struct {
	Password string `validate:"strong_password"`
	SafeText string `validate:"no_html"`
	SQLSafe  string `validate:"no_sql_injection"`
	Path     string `validate:"safe_path"`
	Slug     string `validate:"slug"`
	Phone    string `validate:"phone"`
	Version  string `validate:"semver"`
	Cron     string `validate:"cron"`
	RawJSON  string `validate:"json"`
	Card     string `validate:"credit_card"`
}

type mockDBResolver struct {
	existingRecords map[string]bool
}

func (m *mockDBResolver) Exists(ctx context.Context, table, column string, value any) (bool, error) {
	key := table + ":" + column + ":" + value.(string)
	return m.existingRecords[key], nil
}

type dbSample struct {
	Email    string `validate:"unique=users:email"`
	TenantID string `validate:"exists=tenants:id"`
}

func TestRules_ZeroTrustAndDomain(t *testing.T) {
	eng := New()

	valid := rulesSample{
		Password: "P@ssw0rdSecure!",
		SafeText: "Just a clean normal text without markup",
		SQLSafe:  "SELECT normal column from somewhere",
		Path:     "uploads/avatar.png",
		Slug:     "my-awesome-post-2026",
		Phone:    "+14155552671",
		Version:  "v1.2.3-beta.1",
		Cron:     "0 12 * * ?",
		RawJSON:  `{"status":"active"}`,
		Card:     "4532015112830366", // valid Luhn VISA
	}

	if err := eng.Validate(&valid); err != nil {
		t.Fatalf("expected valid struct to pass, got: %v", err)
	}

	// Test failures
	invalidPassword := valid
	invalidPassword.Password = "weak"
	if err := eng.Validate(&invalidPassword); err == nil {
		t.Errorf("expected weak password to fail")
	}

	invalidHTML := valid
	invalidHTML.SafeText = "<script>alert(1)</script>"
	if err := eng.Validate(&invalidHTML); err == nil {
		t.Errorf("expected script tag to fail no_html")
	}

	invalidSQL := valid
	invalidSQL.SQLSafe = "admin' OR '1'='1' --"
	if err := eng.Validate(&invalidSQL); err == nil {
		t.Errorf("expected SQL injection to fail no_sql_injection")
	}

	invalidPath := valid
	invalidPath.Path = "../../../etc/shadow"
	if err := eng.Validate(&invalidPath); err == nil {
		t.Errorf("expected traversal path to fail safe_path")
	}

	invalidSlug := valid
	invalidSlug.Slug = "invalid slug with spaces!"
	if err := eng.Validate(&invalidSlug); err == nil {
		t.Errorf("expected invalid slug to fail")
	}

	invalidPhone := valid
	invalidPhone.Phone = "not-a-phone-000"
	if err := eng.Validate(&invalidPhone); err == nil {
		t.Errorf("expected invalid phone to fail")
	}

	invalidSemver := valid
	invalidSemver.Version = "v1..2"
	if err := eng.Validate(&invalidSemver); err == nil {
		t.Errorf("expected invalid semver to fail")
	}

	invalidJSON := valid
	invalidJSON.RawJSON = "{invalid-json"
	if err := eng.Validate(&invalidJSON); err == nil {
		t.Errorf("expected invalid JSON to fail")
	}

	invalidCard := valid
	invalidCard.Card = "4532015112830367" // invalid Luhn checksum
	if err := eng.Validate(&invalidCard); err == nil {
		t.Errorf("expected invalid credit card to fail")
	}
}

func TestRules_DatabaseUniquenessAndExistence(t *testing.T) {
	mockDB := &mockDBResolver{
		existingRecords: map[string]bool{
			"users:email:taken@example.com": true,
			"tenants:id:tenant-123":        true,
		},
	}

	eng := New()
	eng.SetDatabaseResolver(mockDB)

	// Test 1: Email is unique, Tenant exists -> OK
	valid := dbSample{
		Email:    "new@example.com",
		TenantID: "tenant-123",
	}
	if err := eng.Validate(&valid); err != nil {
		t.Fatalf("expected valid db checks to pass, got: %v", err)
	}

	// Test 2: Email is taken -> FAIL
	takenEmail := dbSample{
		Email:    "taken@example.com",
		TenantID: "tenant-123",
	}
	if err := eng.Validate(&takenEmail); err == nil {
		t.Fatalf("expected taken email to fail unique validation")
	}

	// Test 3: Tenant does not exist -> FAIL
	missingTenant := dbSample{
		Email:    "new@example.com",
		TenantID: "tenant-999",
	}
	if err := eng.Validate(&missingTenant); err == nil {
		t.Fatalf("expected missing tenant to fail exists validation")
	}
}

type fileUploadSample struct {
	Avatar *multipart.FileHeader `validate:"required,file_max=1MB,file_min=10B,file_ext=.png;.jpg,file_mime=image/png;image/jpeg,file_image=100x100"`
}

func createTestFileHeader(filename string, data []byte) *multipart.FileHeader {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, _ := writer.CreateFormFile("file", filename)
	_, _ = part.Write(data)
	_ = writer.Close()

	reader := multipart.NewReader(body, writer.Boundary())
	form, _ := reader.ReadForm(int64(body.Len()))
	return form.File["file"][0]
}

func TestRules_FileValidation(t *testing.T) {
	eng := New()

	validPNG := []byte{
		0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d,
		0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x06, 0x00, 0x00, 0x00, 0x1f, 0x15, 0xc4, 0x89, 0x00, 0x00, 0x00,
		0x0a, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0x00, 0x01, 0x00, 0x00,
		0x05, 0x00, 0x01, 0x0d, 0x0a, 0x2d, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x49,
		0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82,
	}

	// 1. Valid PNG upload
	valid := fileUploadSample{
		Avatar: createTestFileHeader("avatar.png", validPNG),
	}
	if err := eng.Validate(&valid); err != nil {
		t.Fatalf("expected valid file to pass, got: %v", err)
	}

	// 2. Disallowed extension
	badExt := fileUploadSample{
		Avatar: createTestFileHeader("avatar.exe", validPNG),
	}
	if err := eng.Validate(&badExt); err == nil {
		t.Errorf("expected disallowed extension .exe to fail")
	}

	// 3. File too small
	tooSmall := fileUploadSample{
		Avatar: createTestFileHeader("avatar.png", []byte("tiny")),
	}
	if err := eng.Validate(&tooSmall); err == nil {
		t.Errorf("expected file smaller than 10B to fail")
	}

	// 4. File too large
	bigBuf := make([]byte, 2*1024*1024) // 2MB > 1MB limit
	tooBig := fileUploadSample{
		Avatar: createTestFileHeader("avatar.png", bigBuf),
	}
	if err := eng.Validate(&tooBig); err == nil {
		t.Errorf("expected file larger than 1MB to fail")
	}
}
