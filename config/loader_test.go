package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ztatic-go-framework/security/crypto"
)

type FullAppConfig struct {
	AppName string       `env:"APP_NAME" validate:"required"`
	Port    int          `env:"PORT" envDefault:"8080" validate:"min=1024,max=65535"`
	Secret  SecretString `env:"SECRET_KEY" validate:"secure_secret"`
}

func TestLoad_Success(t *testing.T) {
	tmpDir := t.TempDir()
	_ = os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(`
APP_NAME=ZtaticApp
PORT=9090
SECRET_KEY=dev-secret-key-123
`), 0600)

	cfg, err := Load[FullAppConfig](
		WithEnvDir(tmpDir),
		WithProfile(ProfileDevelopment),
	)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.AppName != "ZtaticApp" {
		t.Errorf("AppName = %q; want ZtaticApp", cfg.AppName)
	}
	if cfg.Port != 9090 {
		t.Errorf("Port = %d; want 9090", cfg.Port)
	}
	if cfg.Secret.Expose() != "dev-secret-key-123" {
		t.Errorf("Secret = %q; want dev-secret-key-123", cfg.Secret.Expose())
	}
}

func TestLoad_ValidationFailure(t *testing.T) {
	tmpDir := t.TempDir()
	// Missing APP_NAME (required) and short secret in production
	_ = os.WriteFile(filepath.Join(tmpDir, ".env"), []byte(`
PORT=80
SECRET_KEY=short
`), 0600)

	_, err := Load[FullAppConfig](
		WithEnvDir(tmpDir),
		WithProfile(ProfileProduction),
	)
	if err == nil {
		t.Fatal("expected Load to fail validation, but succeeded")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "validation") {
		t.Errorf("expected error to mention validation, got: %s", errMsg)
	}
}

func TestLoad_EncryptedSecret(t *testing.T) {
	key := []byte("12345678901234567890123456789012") // 32 bytes
	cs, err := crypto.NewCipherSuite(key)
	if err != nil {
		t.Fatalf("NewCipherSuite failed: %v", err)
	}

	plaintextSecret := "super-secure-production-api-token-value"
	ciphertext, err := cs.Encrypt(plaintextSecret)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	cfg, err := Load[FullAppConfig](
		WithProfile(ProfileDevelopment),
		WithEnvMap(map[string]string{
			"APP_NAME":   "EncryptedApp",
			"PORT":       "3000",
			"SECRET_KEY": "enc:aes-gcm:" + ciphertext,
		}),
		WithCipherSuite(cs),
	)
	if err != nil {
		t.Fatalf("Load with encrypted secret failed: %v", err)
	}

	if cfg.Secret.Expose() != plaintextSecret {
		t.Errorf("Secret.Expose() = %q; want %q", cfg.Secret.Expose(), plaintextSecret)
	}
}

func TestMustLoad_PanicsOnError(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("expected MustLoad to panic on invalid configuration")
		}
	}()

	// Will fail because APP_NAME is required
	_ = MustLoad[FullAppConfig](
		WithEnvMap(map[string]string{}),
	)
}
