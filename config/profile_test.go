package config

import (
	"os"
	"testing"
)

func TestParseProfile(t *testing.T) {
	tests := []struct {
		input    string
		expected Profile
		isDev    bool
		isTest   bool
		isStage  bool
		isProd   bool
	}{
		{"development", ProfileDevelopment, true, false, false, false},
		{"dev", ProfileDevelopment, true, false, false, false},
		{"local", ProfileDevelopment, true, false, false, false},
		{"test", ProfileTest, false, true, false, false},
		{"testing", ProfileTest, false, true, false, false},
		{"staging", ProfileStaging, false, false, true, false},
		{"stage", ProfileStaging, false, false, true, false},
		{"production", ProfileProduction, false, false, false, true},
		{"prod", ProfileProduction, false, false, false, true},
		{"", ProfileDevelopment, true, false, false, false},
		{"custom_env", Profile("custom_env"), false, false, false, false},
	}

	for _, tc := range tests {
		p := ParseProfile(tc.input)
		if p != tc.expected {
			t.Errorf("ParseProfile(%q) = %v; want %v", tc.input, p, tc.expected)
		}
		if p.IsDevelopment() != tc.isDev {
			t.Errorf("Profile(%q).IsDevelopment() = %v; want %v", tc.input, p.IsDevelopment(), tc.isDev)
		}
		if p.IsTest() != tc.isTest {
			t.Errorf("Profile(%q).IsTest() = %v; want %v", tc.input, p.IsTest(), tc.isTest)
		}
		if p.IsStaging() != tc.isStage {
			t.Errorf("Profile(%q).IsStaging() = %v; want %v", tc.input, p.IsStaging(), tc.isStage)
		}
		if p.IsProduction() != tc.isProd {
			t.Errorf("Profile(%q).IsProduction() = %v; want %v", tc.input, p.IsProduction(), tc.isProd)
		}
	}
}

func TestDetectProfile(t *testing.T) {
	// Clean env before test
	os.Unsetenv("ZTATIC_ENV")
	os.Unsetenv("APP_ENV")
	os.Unsetenv("GO_ENV")
	ResetProfile()

	if p := DetectProfile(); p != ProfileDevelopment {
		t.Errorf("expected default ProfileDevelopment, got %v", p)
	}

	os.Setenv("GO_ENV", "testing")
	if p := DetectProfile(); p != ProfileTest {
		t.Errorf("expected GO_ENV to yield ProfileTest, got %v", p)
	}

	os.Setenv("APP_ENV", "staging")
	if p := DetectProfile(); p != ProfileStaging {
		t.Errorf("expected APP_ENV to take precedence over GO_ENV, got %v", p)
	}

	os.Setenv("ZTATIC_ENV", "production")
	if p := DetectProfile(); p != ProfileProduction {
		t.Errorf("expected ZTATIC_ENV to take highest precedence, got %v", p)
	}

	os.Unsetenv("ZTATIC_ENV")
	os.Unsetenv("APP_ENV")
	os.Unsetenv("GO_ENV")
	ResetProfile()
}

func TestActiveProfileAndSetProfile(t *testing.T) {
	ResetProfile()
	SetProfile(ProfileStaging)
	if p := ActiveProfile(); p != ProfileStaging {
		t.Errorf("expected ActiveProfile to be staging, got %v", p)
	}

	SetProfile(ProfileProduction)
	if p := ActiveProfile(); p != ProfileProduction {
		t.Errorf("expected ActiveProfile to be production, got %v", p)
	}
	ResetProfile()
}
