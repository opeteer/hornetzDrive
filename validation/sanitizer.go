package validation

import (
	"context"
	"errors"
	"html"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"sync"
)

var (
	htmlTagRegex      = regexp.MustCompile(`(?is)<script.*?>.*?</script>|<style.*?>.*?</style>|<[^>]*>|<!--.*?-->`)
	whitespaceRegex   = regexp.MustCompile(`[\s\t\n\r]+`)
	phoneFormatRegex  = regexp.MustCompile(`[^\d+]`)
	numericRegex      = regexp.MustCompile(`[^\d]`)
	alphaRegex        = regexp.MustCompile(`[^a-zA-Z]`)
)

// SanitizerFunc is a function that cleans or transforms an input string.
type SanitizerFunc func(in string) string

// Sanitizable is an interface that models can implement to execute
// custom data normalization logic before validation.
type Sanitizable interface {
	Sanitize()
}

// ContextSanitizable is an interface for models requiring context during sanitization.
type ContextSanitizable interface {
	Sanitize(ctx context.Context)
}

var (
	directivesMu sync.RWMutex
	directives   = map[string]SanitizerFunc{
		"trim":            strings.TrimSpace,
		"lower":           strings.ToLower,
		"upper":           strings.ToUpper,
		"collapse_spaces": collapseSpaces,
		"strip_html":      stripHTML,
		"escape_html":     html.EscapeString,
		"strip_control":   stripControlChars,
		"strip_null":      stripNullBytes,
		"numeric_only":    keepNumericOnly,
		"alpha_only":      keepAlphaOnly,
		"normalize_phone": normalizePhoneNumber,
		"clean_path":      cleanPath,
	}
)

// RegisterDirective registers a custom sanitization directive globally.
func RegisterDirective(name string, fn SanitizerFunc) {
	directivesMu.Lock()
	defer directivesMu.Unlock()
	directives[name] = fn
}

// GetDirective retrieves a registered sanitization directive.
func GetDirective(name string) (SanitizerFunc, bool) {
	directivesMu.RLock()
	defer directivesMu.RUnlock()
	fn, ok := directives[name]
	return fn, ok
}

// Sanitize cleans and normalizes a struct or slice in-place using background context.
func Sanitize(i any) error {
	return SanitizeCtx(context.Background(), i)
}

// SanitizeCtx cleans and normalizes a struct or slice in-place with context.
func SanitizeCtx(ctx context.Context, i any) error {
	if i == nil {
		return nil
	}

	val := reflect.ValueOf(i)
	if val.Kind() != reflect.Pointer {
		return errors.New("sanitizer: expects a pointer to struct or slice")
	}

	elem := val.Elem()
	if !elem.IsValid() {
		return nil
	}

	sanitizeValue(ctx, val)
	return nil
}

// SanitizeString applies the given directive sequence to a string.
func SanitizeString(s string, directiveNames ...string) string {
	res := s
	for _, name := range directiveNames {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if fn, ok := GetDirective(name); ok {
			res = fn(res)
		}
	}
	return res
}

func sanitizeValue(ctx context.Context, val reflect.Value) {
	for val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return
		}
		val = val.Elem()
	}

	switch val.Kind() {
	case reflect.Struct:
		t := val.Type()
		for i := 0; i < val.NumField(); i++ {
			fieldVal := val.Field(i)
			fieldMeta := t.Field(i)

			// Process sanitize tag
			tag := fieldMeta.Tag.Get("sanitize")
			if tag != "" && fieldVal.CanSet() {
				if fieldVal.Kind() == reflect.String {
					cleaned := applyDirectives(fieldVal.String(), tag)
					fieldVal.SetString(cleaned)
				} else if fieldVal.Kind() == reflect.Slice && fieldVal.Type().Elem().Kind() == reflect.String {
					for j := 0; j < fieldVal.Len(); j++ {
						elemVal := fieldVal.Index(j)
						cleaned := applyDirectives(elemVal.String(), tag)
						elemVal.SetString(cleaned)
					}
				}
			}

			// Recursively inspect nested fields
			if fieldVal.Kind() == reflect.Struct || fieldVal.Kind() == reflect.Pointer || fieldVal.Kind() == reflect.Slice {
				sanitizeValue(ctx, fieldVal)
			}
		}

		// Execute interface hooks after field tag normalization
		if val.CanAddr() {
			addr := val.Addr().Interface()
			if cs, ok := addr.(ContextSanitizable); ok {
				cs.Sanitize(ctx)
			} else if s, ok := addr.(Sanitizable); ok {
				s.Sanitize()
			}
		}

	case reflect.Slice:
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.Struct || elem.Kind() == reflect.Pointer {
				sanitizeValue(ctx, elem)
			}
		}
	}
}

func applyDirectives(val string, tag string) string {
	parts := strings.Split(tag, ",")
	res := val
	for _, part := range parts {
		dName := strings.TrimSpace(part)
		if dName == "" {
			continue
		}
		if fn, ok := GetDirective(dName); ok {
			res = fn(res)
		}
	}
	return res
}

// Built-in sanitizer functions

func collapseSpaces(in string) string {
	trimmed := strings.TrimSpace(in)
	return whitespaceRegex.ReplaceAllString(trimmed, " ")
}

func stripHTML(in string) string {
	return strings.TrimSpace(htmlTagRegex.ReplaceAllString(in, ""))
}

func stripControlChars(in string) string {
	var sb strings.Builder
	sb.Grow(len(in))
	for _, r := range in {
		if r == '\n' || r == '\r' || r == '\t' {
			sb.WriteRune(r)
			continue
		}
		if r < 32 || r == 127 {
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func stripNullBytes(in string) string {
	return strings.ReplaceAll(in, "\x00", "")
}

func keepNumericOnly(in string) string {
	return numericRegex.ReplaceAllString(in, "")
}

func keepAlphaOnly(in string) string {
	return alphaRegex.ReplaceAllString(in, "")
}

func normalizePhoneNumber(in string) string {
	clean := phoneFormatRegex.ReplaceAllString(in, "")
	// Ensure at most one leading +
	if strings.Contains(clean, "+") {
		clean = "+" + strings.ReplaceAll(clean, "+", "")
	}
	return clean
}

func cleanPath(in string) string {
	cleaned := filepath.Clean(in)
	// Remove directory traversal sequences
	cleaned = strings.TrimPrefix(cleaned, "/")
	for strings.HasPrefix(cleaned, "../") {
		cleaned = strings.TrimPrefix(cleaned, "../")
	}
	for strings.HasPrefix(cleaned, "..\\") {
		cleaned = strings.TrimPrefix(cleaned, "..\\")
	}
	if cleaned == ".." || cleaned == "." {
		return ""
	}
	return strings.ReplaceAll(cleaned, "\x00", "")
}
