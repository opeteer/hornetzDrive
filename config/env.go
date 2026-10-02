package config

import (
	"bufio"
	"encoding"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ztatic-go-framework/security/crypto"
)

// EnvMap represents a key-value mapping of environment variables.
type EnvMap map[string]string

var (
	varExpansionRegex = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*(?::-?[^}]*)?)\}`)
)

// ParseDotenv reads .env formatted content and returns an EnvMap.
// Supports:
// - Empty lines and '#' comments
// - 'export ' prefix stripping
// - Single and double quoted values with escape sequences
// - Variable interpolation: ${VAR} and ${VAR:-default}
func ParseDotenv(r io.Reader) (EnvMap, error) {
	result := make(EnvMap)
	scanner := bufio.NewScanner(r)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and full line comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Optional 'export ' keyword
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}

		// Split on the first '='
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		if key == "" {
			continue
		}

		val := strings.TrimSpace(parts[1])
		val = parseDotenvValue(val)
		result[key] = val
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading dotenv content: %w", err)
	}

	// Expand variables within the parsed map
	expandVariables(result)

	return result, nil
}

func parseDotenvValue(val string) string {
	if len(val) >= 2 {
		// Double-quoted string
		if val[0] == '"' && val[len(val)-1] == '"' {
			inner := val[1 : len(val)-1]
			inner = strings.ReplaceAll(inner, `\n`, "\n")
			inner = strings.ReplaceAll(inner, `\t`, "\t")
			inner = strings.ReplaceAll(inner, `\r`, "\r")
			inner = strings.ReplaceAll(inner, `\"`, `"`)
			inner = strings.ReplaceAll(inner, `\\`, `\`)
			return inner
		}
		// Single-quoted string: literal content
		if val[0] == '\'' && val[len(val)-1] == '\'' {
			return val[1 : len(val)-1]
		}
	}

	// Unquoted string: strip trailing inline comments
	if idx := strings.Index(val, " #"); idx != -1 {
		val = strings.TrimSpace(val[:idx])
	}
	return val
}

// expandVariables performs variable substitution (${VAR} or ${VAR:-default}) across the env map.
func expandVariables(env EnvMap) {
	for k, v := range env {
		env[k] = expandString(v, env)
	}
}

// expandString replaces ${VAR} or ${VAR:-default} with values from env map or os.Getenv.
func expandString(s string, lookup EnvMap) string {
	return varExpansionRegex.ReplaceAllStringFunc(s, func(match string) string {
		inner := match[2 : len(match)-1] // strip ${ and }
		var varName, defaultVal string

		if idx := strings.Index(inner, ":-"); idx != -1 {
			varName = inner[:idx]
			defaultVal = inner[idx+2:]
		} else if idx := strings.Index(inner, ":"); idx != -1 {
			varName = inner[:idx]
			defaultVal = inner[idx+1:]
		} else {
			varName = inner
		}

		if val, exists := lookup[varName]; exists && val != "" {
			return val
		}
		if val := os.Getenv(varName); val != "" {
			return val
		}
		return defaultVal
	})
}

// LoadDotenvFiles loads dotenv files cascading in order:
// 1. .env (base defaults)
// 2. .env.local (local developer uncommitted overrides)
// 3. .env.{profile} (e.g. .env.development, .env.production)
// 4. .env.{profile}.local
// Files that do not exist are silently ignored.
func LoadDotenvFiles(dir string, profile Profile) (EnvMap, error) {
	if dir == "" {
		dir = "."
	}

	p := profile.String()
	files := []string{
		filepath.Join(dir, ".env"),
		filepath.Join(dir, ".env.local"),
		filepath.Join(dir, fmt.Sprintf(".env.%s", p)),
		filepath.Join(dir, fmt.Sprintf(".env.%s.local", p)),
	}

	combined := make(EnvMap)

	for _, file := range files {
		if _, err := os.Stat(file); err == nil {
			f, err := os.Open(file)
			if err != nil {
				return nil, fmt.Errorf("failed to open dotenv file %q: %w", file, err)
			}
			parsed, err := ParseDotenv(f)
			_ = f.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to parse dotenv file %q: %w", file, err)
			}
			for k, v := range parsed {
				combined[k] = v
			}
		}
	}

	return combined, nil
}

// BuildRuntimeEnv merges dotenv files and process OS environment variables.
// OS environment variables always take precedence over dotenv files.
func BuildRuntimeEnv(dir string, profile Profile) (EnvMap, error) {
	dotenv, err := LoadDotenvFiles(dir, profile)
	if err != nil {
		return nil, err
	}

	result := make(EnvMap, len(dotenv))
	for k, v := range dotenv {
		result[k] = v
	}

	// Overlay process environment variables
	for _, envPair := range os.Environ() {
		parts := strings.SplitN(envPair, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}

	// Perform final expansion pass with all OS + dotenv values
	expandVariables(result)

	return result, nil
}

// StructBinder binds an EnvMap to Go struct pointers via reflection.
type StructBinder struct {
	env         EnvMap
	cipherSuite *crypto.CipherSuite
}

// NewStructBinder initializes a struct binder with the given environment map.
func NewStructBinder(env EnvMap, cs *crypto.CipherSuite) *StructBinder {
	return &StructBinder{
		env:         env,
		cipherSuite: cs,
	}
}

// Bind populates the destination struct pointer with environment variables.
func (b *StructBinder) Bind(dest any) error {
	v := reflect.ValueOf(dest)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("config: Bind requires a non-nil struct pointer, got %T", dest)
	}

	elem := v.Elem()
	if elem.Kind() != reflect.Struct {
		return fmt.Errorf("config: Bind requires a pointer to struct, got pointer to %s", elem.Kind())
	}

	return b.bindStruct(elem, "")
}

func (b *StructBinder) bindStruct(val reflect.Value, prefix string) error {
	t := val.Type()

	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		fieldVal := val.Field(i)

		if !fieldVal.CanSet() {
			continue
		}

		// Handle embedded structs and nested structs
		fieldPrefix := prefix
		if customPrefix := field.Tag.Get("envPrefix"); customPrefix != "" {
			fieldPrefix += customPrefix
		}

		// Check if it's a struct (excluding types like time.Time, url.URL, SecretString)
		if isNestedStruct(field.Type) {
			target := fieldVal
			if target.Kind() == reflect.Pointer {
				if target.IsNil() {
					target.Set(reflect.New(field.Type.Elem()))
				}
				target = target.Elem()
			}
			if err := b.bindStruct(target, fieldPrefix); err != nil {
				return err
			}
			continue
		}

		// Environment variable name resolution
		envTag := field.Tag.Get("env")
		if envTag == "-" {
			continue
		}

		var envKey string
		if envTag != "" {
			envKey = fieldPrefix + envTag
		} else {
			// Default to UPPER_SNAKE_CASE of field name if env tag omitted
			envKey = fieldPrefix + toUpperSnakeCase(field.Name)
		}

		// Lookup value: env map -> envDefault tag
		rawVal, found := b.env[envKey]
		if !found || strings.TrimSpace(rawVal) == "" {
			if defVal, ok := field.Tag.Lookup("envDefault"); ok {
				rawVal = defVal
				found = true
			}
		}

		if !found {
			continue
		}

		// Resolve secret wrappers or file:// or enc:aes-gcm:
		separator := field.Tag.Get("envSeparator")
		if separator == "" {
			separator = ","
		}

		if err := b.bindField(fieldVal, rawVal, separator); err != nil {
			return fmt.Errorf("failed to bind field %s (%s): %w", field.Name, envKey, err)
		}
	}

	return nil
}

func (b *StructBinder) bindField(val reflect.Value, raw string, separator string) error {
	// 1. Resolve encrypted or file-based secret if applicable
	resolvedRaw, err := ResolveSecret(raw, b.cipherSuite)
	if err != nil {
		return err
	}

	// 2. Custom SecretString type
	if val.Type() == reflect.TypeOf(SecretString{}) {
		val.Set(reflect.ValueOf(NewSecretString(resolvedRaw)))
		return nil
	}
	if val.Type() == reflect.TypeOf(&SecretString{}) {
		s := NewSecretString(resolvedRaw)
		val.Set(reflect.ValueOf(&s))
		return nil
	}

	// 3. TextUnmarshaler interface
	if val.CanAddr() {
		if u, ok := val.Addr().Interface().(encoding.TextUnmarshaler); ok {
			return u.UnmarshalText([]byte(resolvedRaw))
		}
	}

	// 4. Pointer types
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			val.Set(reflect.New(val.Type().Elem()))
		}
		return b.bindField(val.Elem(), resolvedRaw, separator)
	}

	// 5. Primitive and standard types
	switch val.Kind() {
	case reflect.String:
		val.SetString(resolvedRaw)
		return nil

	case reflect.Bool:
		bVal, err := parseBool(resolvedRaw)
		if err != nil {
			return err
		}
		val.SetBool(bVal)
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		// Special check for time.Duration
		if val.Type() == reflect.TypeOf(time.Duration(0)) {
			d, err := time.ParseDuration(resolvedRaw)
			if err != nil {
				return fmt.Errorf("invalid duration %q: %w", resolvedRaw, err)
			}
			val.SetInt(int64(d))
			return nil
		}
		n, err := strconv.ParseInt(resolvedRaw, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid integer %q: %w", resolvedRaw, err)
		}
		val.SetInt(n)
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		n, err := strconv.ParseUint(resolvedRaw, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid unsigned integer %q: %w", resolvedRaw, err)
		}
		val.SetUint(n)
		return nil

	case reflect.Float32, reflect.Float64:
		f, err := strconv.ParseFloat(resolvedRaw, 64)
		if err != nil {
			return fmt.Errorf("invalid float %q: %w", resolvedRaw, err)
		}
		val.SetFloat(f)
		return nil

	case reflect.Slice:
		return b.bindSlice(val, resolvedRaw, separator)

	case reflect.Struct:
		// time.Time
		if val.Type() == reflect.TypeOf(time.Time{}) {
			t, err := time.Parse(time.RFC3339, resolvedRaw)
			if err != nil {
				t, err = time.Parse("2006-01-02", resolvedRaw)
				if err != nil {
					return fmt.Errorf("invalid time %q: %w", resolvedRaw, err)
				}
			}
			val.Set(reflect.ValueOf(t))
			return nil
		}
		// url.URL
		if val.Type() == reflect.TypeOf(url.URL{}) {
			u, err := url.Parse(resolvedRaw)
			if err != nil {
				return fmt.Errorf("invalid url %q: %w", resolvedRaw, err)
			}
			val.Set(reflect.ValueOf(*u))
			return nil
		}
	}

	return fmt.Errorf("unsupported configuration type: %s", val.Type())
}

func (b *StructBinder) bindSlice(val reflect.Value, raw string, separator string) error {
	parts := strings.Split(raw, separator)
	slice := reflect.MakeSlice(val.Type(), 0, len(parts))

	for _, p := range parts {
		item := strings.TrimSpace(p)
		if item == "" {
			continue
		}
		elem := reflect.New(val.Type().Elem()).Elem()
		if err := b.bindField(elem, item, separator); err != nil {
			return err
		}
		slice = reflect.Append(slice, elem)
	}

	val.Set(slice)
	return nil
}

func isNestedStruct(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	// Exclude recognized value struct types
	switch t {
	case reflect.TypeOf(time.Time{}),
		reflect.TypeOf(url.URL{}),
		reflect.TypeOf(SecretString{}):
		return false
	default:
		return true
	}
}

func parseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "y", "on", "t":
		return true, nil
	case "false", "0", "no", "n", "off", "f", "":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean %q", s)
	}
}

func toUpperSnakeCase(s string) string {
	var result strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			prev := rune(s[i-1])
			if !(prev >= 'A' && prev <= 'Z') {
				result.WriteRune('_')
			}
		}
		result.WriteRune(r)
	}
	return strings.ToUpper(result.String())
}
