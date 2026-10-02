package config

import (
	"fmt"
	"os"

	"ztatic-go-framework/security/crypto"
)

// LoaderOptions encapsulates configuration loading options.
type LoaderOptions struct {
	Profile        Profile
	EnvDir         string
	Prefix         string
	CipherSuite    *crypto.CipherSuite
	SkipValidation bool
	ExplicitFiles  []string
	ExplicitEnv    EnvMap
}

// Option configures how configuration is loaded.
type Option func(*LoaderOptions)

// WithProfile explicitly specifies the profile to use (e.g. ProfileProduction).
func WithProfile(p Profile) Option {
	return func(o *LoaderOptions) {
		o.Profile = p
	}
}

// WithEnvDir sets the directory where .env files are located (default: ".").
func WithEnvDir(dir string) Option {
	return func(o *LoaderOptions) {
		o.EnvDir = dir
	}
}

// WithPrefix sets a global prefix for all environment variables (e.g. "APP_").
func WithPrefix(prefix string) Option {
	return func(o *LoaderOptions) {
		o.Prefix = prefix
	}
}

// WithCipherSuite provides an AES-256-GCM cipher suite for decrypting secrets.
func WithCipherSuite(cs *crypto.CipherSuite) Option {
	return func(o *LoaderOptions) {
		o.CipherSuite = cs
	}
}

// WithCipherKey initializes an AES-256-GCM cipher suite from a 32-byte key.
func WithCipherKey(key []byte) Option {
	return func(o *LoaderOptions) {
		if cs, err := crypto.NewCipherSuite(key); err == nil {
			o.CipherSuite = cs
		}
	}
}

// SkipValidation disables struct validation at startup.
func SkipValidation() Option {
	return func(o *LoaderOptions) {
		o.SkipValidation = true
	}
}

// WithEnvFiles specifies explicit dotenv files to load in order.
func WithEnvFiles(files ...string) Option {
	return func(o *LoaderOptions) {
		o.ExplicitFiles = files
	}
}

// WithEnvMap injects explicit key-value pairs for testing or programmatic overrides.
func WithEnvMap(env map[string]string) Option {
	return func(o *LoaderOptions) {
		if o.ExplicitEnv == nil {
			o.ExplicitEnv = make(EnvMap)
		}
		for k, v := range env {
			o.ExplicitEnv[k] = v
		}
	}
}

// Load loads, decodes, and validates configuration into a new instance of T.
func Load[T any](opts ...Option) (*T, error) {
	var cfg T
	if err := LoadInto(&cfg, opts...); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// MustLoad loads configuration into T, or panics if validation or binding fails.
// Ideal for application entrypoints (main.go) to guarantee fail-fast behavior.
func MustLoad[T any](opts ...Option) *T {
	cfg, err := Load[T](opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ FATAL: Configuration failed to load:\n%v\n\n", err)
		panic(fmt.Sprintf("config: failed to load configuration: %v", err))
	}
	return cfg
}

// LoadInto populates an existing struct pointer with configuration data.
func LoadInto(dest any, opts ...Option) error {
	options := LoaderOptions{
		Profile: ActiveProfile(),
		EnvDir:  ".",
	}
	for _, opt := range opts {
		opt(&options)
	}

	// 1. Build runtime environment map (dotenv cascading + OS environ)
	var runtimeEnv EnvMap
	var err error

	if len(options.ExplicitFiles) > 0 {
		runtimeEnv = make(EnvMap)
		for _, f := range options.ExplicitFiles {
			if file, err := os.Open(f); err == nil {
				parsed, err := ParseDotenv(file)
				_ = file.Close()
				if err != nil {
					return fmt.Errorf("failed to parse file %q: %w", f, err)
				}
				for k, v := range parsed {
					runtimeEnv[k] = v
				}
			}
		}
	} else {
		runtimeEnv, err = BuildRuntimeEnv(options.EnvDir, options.Profile)
		if err != nil {
			return fmt.Errorf("failed to build runtime environment: %w", err)
		}
	}

	// 2. Overlay explicit programmatic overrides
	for k, v := range options.ExplicitEnv {
		runtimeEnv[k] = v
	}

	// 3. Resolve cipher suite from env ZTATIC_CIPHER_KEY if not explicitly provided
	if options.CipherSuite == nil {
		if keyStr := runtimeEnv["ZTATIC_CIPHER_KEY"]; len(keyStr) == 32 {
			if cs, err := crypto.NewCipherSuite([]byte(keyStr)); err == nil {
				options.CipherSuite = cs
			}
		}
	}

	// 4. Bind into struct via reflection
	binder := NewStructBinder(runtimeEnv, options.CipherSuite)
	if err := binder.Bind(dest); err != nil {
		return fmt.Errorf("config binding failed: %w", err)
	}

	// 5. Fail-fast validation
	if !options.SkipValidation {
		validator := NewConfigValidator(options.Profile)
		if err := validator.Validate(dest); err != nil {
			return err
		}
	}

	return nil
}
