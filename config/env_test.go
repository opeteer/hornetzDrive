package config

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseDotenv(t *testing.T) {
	input := `
# Comment line
APP_NAME=MyService
export PORT=9000
DEBUG=true
TIMEOUT=15s
QUOTED="hello \"world\"\nnewline"
SINGLE='literal $variable'
INLINE=value # this is an inline comment
EMPTY=
URL=http://localhost:8080/api
BASE_URL=${URL}/v1
FALLBACK=${UNSET_VAR:-default_val}
`

	env, err := ParseDotenv(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseDotenv failed: %v", err)
	}

	expected := map[string]string{
		"APP_NAME": "MyService",
		"PORT":     "9000",
		"DEBUG":    "true",
		"TIMEOUT":  "15s",
		"QUOTED":   "hello \"world\"\nnewline",
		"SINGLE":   "literal $variable",
		"INLINE":   "value",
		"EMPTY":    "",
		"URL":      "http://localhost:8080/api",
		"BASE_URL": "http://localhost:8080/api/v1",
		"FALLBACK": "default_val",
	}

	for k, want := range expected {
		if got := env[k]; got != want {
			t.Errorf("env[%q] = %q; want %q", k, got, want)
		}
	}
}

func TestCascadingDotenv(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. .env
	_ = os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(`
PORT=8080
DB_HOST=localhost
LOG_LEVEL=info
FEATURE_X=false
`), 0600)

	// 2. .env.local
	_ = os.WriteFile(filepath.Join(tmpDir, ".env.local"), []byte(`
DB_HOST=127.0.0.1
`), 0600)

	// 3. .env.staging
	_ = os.WriteFile(filepath.Join(tmpDir, ".env.staging"), []byte(`
LOG_LEVEL=warn
FEATURE_X=true
`), 0600)

	// 4. .env.staging.local
	_ = os.WriteFile(filepath.Join(tmpDir, ".env.staging.local"), []byte(`
FEATURE_X=override_local
`), 0600)

	env, err := LoadDotenvFiles(tmpDir, ProfileStaging)
	if err != nil {
		t.Fatalf("LoadDotenvFiles failed: %v", err)
	}

	if env["PORT"] != "8080" {
		t.Errorf("PORT = %q; want 8080", env["PORT"])
	}
	if env["DB_HOST"] != "127.0.0.1" {
		t.Errorf("DB_HOST = %q; want 127.0.0.1", env["DB_HOST"])
	}
	if env["LOG_LEVEL"] != "warn" {
		t.Errorf("LOG_LEVEL = %q; want warn", env["LOG_LEVEL"])
	}
	if env["FEATURE_X"] != "override_local" {
		t.Errorf("FEATURE_X = %q; want override_local", env["FEATURE_X"])
	}
}

type DatabaseConfig struct {
	Host     string       `env:"HOST" envDefault:"localhost"`
	Port     int          `env:"PORT" envDefault:"5432"`
	Password SecretString `env:"PASSWORD"`
}

type TestAppConfig struct {
	AppName    string         `env:"APP_NAME" envDefault:"DefaultApp"`
	Port       int            `env:"PORT" envDefault:"8080"`
	Debug      bool           `env:"DEBUG"`
	Timeout    time.Duration  `env:"TIMEOUT" envDefault:"5s"`
	BaseURL    url.URL        `env:"BASE_URL"`
	AllowedIPs []string       `env:"ALLOWED_IPS" envSeparator:","`
	DB         DatabaseConfig `envPrefix:"DB_"`
}

func TestStructBinder(t *testing.T) {
	env := EnvMap{
		"APP_NAME":    "CustomApp",
		"DEBUG":       "true",
		"TIMEOUT":     "10s",
		"BASE_URL":    "https://api.example.com",
		"ALLOWED_IPS": "10.0.0.1, 10.0.0.2, 10.0.0.3",
		"DB_HOST":     "postgres.internal",
		"DB_PASSWORD": "super-secret-db-pwd",
	}

	var cfg TestAppConfig
	binder := NewStructBinder(env, nil)
	if err := binder.Bind(&cfg); err != nil {
		t.Fatalf("Bind failed: %v", err)
	}

	if cfg.AppName != "CustomApp" {
		t.Errorf("AppName = %q; want CustomApp", cfg.AppName)
	}
	if cfg.Port != 8080 { // from envDefault
		t.Errorf("Port = %d; want 8080", cfg.Port)
	}
	if !cfg.Debug {
		t.Errorf("Debug = false; want true")
	}
	if cfg.Timeout != 10*time.Second {
		t.Errorf("Timeout = %v; want 10s", cfg.Timeout)
	}
	if cfg.BaseURL.String() != "https://api.example.com" {
		t.Errorf("BaseURL = %v; want https://api.example.com", cfg.BaseURL.String())
	}
	if len(cfg.AllowedIPs) != 3 || cfg.AllowedIPs[0] != "10.0.0.1" {
		t.Errorf("AllowedIPs = %v; want [10.0.0.1, 10.0.0.2, 10.0.0.3]", cfg.AllowedIPs)
	}
	if cfg.DB.Host != "postgres.internal" {
		t.Errorf("DB.Host = %q; want postgres.internal", cfg.DB.Host)
	}
	if cfg.DB.Port != 5432 {
		t.Errorf("DB.Port = %d; want 5432", cfg.DB.Port)
	}
	if cfg.DB.Password.Expose() != "super-secret-db-pwd" {
		t.Errorf("DB.Password = %q; want super-secret-db-pwd", cfg.DB.Password.Expose())
	}
}
