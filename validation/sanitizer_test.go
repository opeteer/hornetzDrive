package validation

import (
	"context"
	"testing"
)

type userProfile struct {
	Username  string   `sanitize:"trim,lower"`
	Email     string   `sanitize:"trim,lower"`
	Bio       string   `sanitize:"trim,strip_html,collapse_spaces"`
	Phone     string   `sanitize:"normalize_phone"`
	Tags      []string `sanitize:"trim,lower"`
	AvatarURL string   `sanitize:"trim,strip_control"`
	FilePath  string   `sanitize:"clean_path"`
}

type nestedAddress struct {
	Street string `sanitize:"trim,title"`
	City   string `sanitize:"trim,upper"`
}

type companyProfile struct {
	Name    string        `sanitize:"trim"`
	Address nestedAddress
}

type hookModel struct {
	Title string `sanitize:"trim"`
	HookCalled bool
}

func (h *hookModel) Sanitize() {
	h.HookCalled = true
	h.Title = "sanitized:" + h.Title
}

type contextHookModel struct {
	Tenant string
}

func (c *contextHookModel) Sanitize(ctx context.Context) {
	if val, ok := ctx.Value("tenant").(string); ok {
		c.Tenant = val
	}
}

func TestSanitizer_BasicDirectives(t *testing.T) {
	u := &userProfile{
		Username:  "  Alice_Wonderland  ",
		Email:     "  ALICE@Example.COM  ",
		Bio:       "  <script>alert('xss')</script> Hello \n\n world! <b>bold</b>  ",
		Phone:     "+1 (555) 123-4567",
		Tags:      []string{" GoLang ", "  ZTATIC  "},
		AvatarURL: "avatar\x00_pic\x1f.png",
		FilePath:  "../../etc/passwd",
	}

	if err := Sanitize(u); err != nil {
		t.Fatalf("unexpected sanitization error: %v", err)
	}

	if u.Username != "alice_wonderland" {
		t.Errorf("expected 'alice_wonderland', got '%s'", u.Username)
	}
	if u.Email != "alice@example.com" {
		t.Errorf("expected 'alice@example.com', got '%s'", u.Email)
	}
	if u.Bio != "Hello world! bold" {
		t.Errorf("expected 'Hello world! bold', got '%s'", u.Bio)
	}
	if u.Phone != "+15551234567" {
		t.Errorf("expected '+15551234567', got '%s'", u.Phone)
	}
	if len(u.Tags) != 2 || u.Tags[0] != "golang" || u.Tags[1] != "ztatic" {
		t.Errorf("unexpected tags: %+v", u.Tags)
	}
	if u.AvatarURL != "avatar_pic.png" {
		t.Errorf("expected 'avatar_pic.png', got '%s'", u.AvatarURL)
	}
	if u.FilePath != "etc/passwd" {
		t.Errorf("expected 'etc/passwd', got '%s'", u.FilePath)
	}
}

func TestSanitizer_NestedStruct(t *testing.T) {
	c := &companyProfile{
		Name: "  Acme Corp  ",
		Address: nestedAddress{
			Street: "  123 Main St  ",
			City:   "  new york  ",
		},
	}

	if err := Sanitize(c); err != nil {
		t.Fatalf("unexpected sanitization error: %v", err)
	}

	if c.Name != "Acme Corp" {
		t.Errorf("expected 'Acme Corp', got '%s'", c.Name)
	}
	if c.Address.City != "NEW YORK" {
		t.Errorf("expected 'NEW YORK', got '%s'", c.Address.City)
	}
}

func TestSanitizer_InterfaceHooks(t *testing.T) {
	h := &hookModel{Title: "  My Article  "}
	if err := Sanitize(h); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !h.HookCalled {
		t.Errorf("expected Sanitize() hook to be called")
	}
	if h.Title != "sanitized:My Article" {
		t.Errorf("expected 'sanitized:My Article', got '%s'", h.Title)
	}

	// Context hook
	ctx := context.WithValue(context.Background(), "tenant", "tenant-123")
	ch := &contextHookModel{}
	if err := SanitizeCtx(ctx, ch); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ch.Tenant != "tenant-123" {
		t.Errorf("expected tenant-123, got '%s'", ch.Tenant)
	}
}

func TestSanitizeString(t *testing.T) {
	res := SanitizeString("  <h1>Hello</h1>   world   ", "strip_html", "collapse_spaces")
	if res != "Hello world" {
		t.Errorf("expected 'Hello world', got '%s'", res)
	}
}
