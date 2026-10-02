package validation

import (
	"context"
	"encoding/json"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"mime/multipart"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"github.com/gabriel-vasile/mimetype"
	"github.com/go-playground/validator/v10"
)

var (
	slugRegex = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)
	semverRegex = regexp.MustCompile(`^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$`)
	xssCheckRegex = regexp.MustCompile(`(?is)<\s*script\b[^>]*>|<\s*/\s*script\s*>|javascript\s*:|\bon(load|error|click|dblclick|mouse\w+|key\w+|focus\w*|blur|change|submit|input)\s*=|<\s*(iframe|object|embed|applet)\b[^>]*>`)
	sqliCheckRegexes = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\bunion\s*(all\s+|distinct\s+)?select\b`),
		regexp.MustCompile(`(?i)(;\s*|\b(union|select)\b.*?)\b(drop\s+(table|database)|truncate\s+table|alter\s+table)\b`),
		regexp.MustCompile(`(?i)\b(exec|execute)\s*(xp_\w+|sp_\w+|immediate|master\.|\(@?|@\w+)`),
		regexp.MustCompile(`(?i)('\s*(or|and)\s*'?\d+'?\s*=\s*'?\d+'?|'\s*(or|and)\s*'\w+'\s*=\s*'\w+')`),
		regexp.MustCompile(`(?i)('\s*(or|and)\s*.*?--|'\s*--|;\s*--)`),
	}

	customRulesMu  sync.RWMutex
	customRules    = make(map[string]validator.Func)
	customCtxRules = make(map[string]validator.FuncCtx)
)

// RegisterRule registers a custom validation rule tag globally.
func RegisterRule(tag string, fn validator.Func) {
	customRulesMu.Lock()
	defer customRulesMu.Unlock()
	customRules[tag] = fn
}

// RegisterRuleWithContext registers a custom context-aware validation rule tag globally.
func RegisterRuleWithContext(tag string, fn validator.FuncCtx) {
	customRulesMu.Lock()
	defer customRulesMu.Unlock()
	customCtxRules[tag] = fn
}

func registerBuiltInRules(v *validator.Validate, getResolver func() DatabaseResolver) {
	// Zero-Trust Security Rules
	_ = v.RegisterValidation("strong_password", validateStrongPassword)
	_ = v.RegisterValidation("no_html", validateNoHTML)
	_ = v.RegisterValidation("xss_safe", validateNoHTML)
	_ = v.RegisterValidation("no_sql_injection", validateNoSQLInjection)
	_ = v.RegisterValidation("safe_path", validateSafePath)

	// Domain & Format Rules
	_ = v.RegisterValidation("slug", validateSlug)
	_ = v.RegisterValidation("phone", validatePhone)
	_ = v.RegisterValidation("semver", validateSemVer)
	_ = v.RegisterValidation("cron", validateCron)
	_ = v.RegisterValidation("json", validateJSON)
	_ = v.RegisterValidation("credit_card", validateCreditCard)

	// Context-Aware Database Rules
	_ = v.RegisterValidationCtx("unique", makeValidateUnique(getResolver))
	_ = v.RegisterValidationCtx("exists", makeValidateExists(getResolver))

	// File Upload Rules
	_ = v.RegisterValidation("file_max", validateFileMax)
	_ = v.RegisterValidation("file_min", validateFileMin)
	_ = v.RegisterValidation("file_ext", validateFileExt)
	_ = v.RegisterValidation("file_mime", validateFileMIME)
	_ = v.RegisterValidation("file_image", validateFileImage)

	// Register user-defined custom rules
	customRulesMu.RLock()
	defer customRulesMu.RUnlock()
	for tag, fn := range customRules {
		_ = v.RegisterValidation(tag, fn)
	}
	for tag, fn := range customCtxRules {
		_ = v.RegisterValidationCtx(tag, fn)
	}
}

// Rule implementations

func validateStrongPassword(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	minLen := 8
	if param := fl.Param(); param != "" {
		if p, err := strconv.Atoi(param); err == nil && p > 0 {
			minLen = p
		}
	}

	if len(val) < minLen {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range val {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSpecial
}

func validateNoHTML(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	if xssCheckRegex.MatchString(val) {
		return false
	}
	// Check for raw html tags like <div ...> or <b>
	return !htmlTagRegex.MatchString(val)
}

func validateNoSQLInjection(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	for _, re := range sqliCheckRegexes {
		if re.MatchString(val) {
			return false
		}
	}
	return true
}

func validateSafePath(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	if strings.Contains(val, "\x00") {
		return false
	}
	// Check directory traversal
	cleaned := filepath.Clean(val)
	if strings.HasPrefix(cleaned, "..") || strings.Contains(val, "../") || strings.Contains(val, `..\`) {
		return false
	}
	return true
}

func validateSlug(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	return slugRegex.MatchString(val)
}

func validatePhone(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	return phoneRegex.MatchString(val)
}

func validateSemVer(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	return semverRegex.MatchString(val)
}

func validateCron(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	fields := strings.Fields(val)
	if len(fields) != 5 {
		return false
	}
	cronFieldPattern := regexp.MustCompile(`^[\d\*\-\,\/\?a-zA-Z]+$`)
	for _, field := range fields {
		if !cronFieldPattern.MatchString(field) {
			return false
		}
	}
	return true
}

func validateJSON(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	if val == "" {
		return true
	}
	return json.Valid([]byte(val))
}

func validateCreditCard(fl validator.FieldLevel) bool {
	val := fl.Field().String()
	val = strings.ReplaceAll(val, " ", "")
	val = strings.ReplaceAll(val, "-", "")
	if len(val) < 13 || len(val) > 19 {
		return false
	}
	// Luhn Algorithm
	var sum int
	alternate := false
	for i := len(val) - 1; i >= 0; i-- {
		r := rune(val[i])
		if !unicode.IsDigit(r) {
			return false
		}
		digit := int(r - '0')
		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
		alternate = !alternate
	}
	return sum%10 == 0
}

func parseTableAndCol(param string) (string, string, bool) {
	parts := strings.FieldsFunc(param, func(r rune) bool {
		return r == ':' || r == '/' || r == '.' || r == ','
	})
	if len(parts) < 2 {
		return "", "", false
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), true
}

func makeValidateUnique(getResolver func() DatabaseResolver) validator.FuncCtx {
	return func(ctx context.Context, fl validator.FieldLevel) bool {
		table, column, ok := parseTableAndCol(fl.Param())
		if !ok {
			return true // misconfigured rule tag, do not block
		}

		resolver := ResolverFromContext(ctx)
		if resolver == nil && getResolver != nil {
			resolver = getResolver()
		}
		if resolver == nil {
			// No database resolver configured; treat as passing
			return true
		}

		exists, err := resolver.Exists(ctx, table, column, fl.Field().Interface())
		if err != nil {
			return false
		}
		return !exists
	}
}

func makeValidateExists(getResolver func() DatabaseResolver) validator.FuncCtx {
	return func(ctx context.Context, fl validator.FieldLevel) bool {
		table, column, ok := parseTableAndCol(fl.Param())
		if !ok {
			return true
		}

		resolver := ResolverFromContext(ctx)
		if resolver == nil && getResolver != nil {
			resolver = getResolver()
		}
		if resolver == nil {
			return true
		}

		exists, err := resolver.Exists(ctx, table, column, fl.Field().Interface())
		if err != nil {
			return false
		}
		return exists
	}
}

// File validation rule implementations

func validateFileMax(fl validator.FieldLevel) bool {
	fhs := extractFileHeaders(fl)
	if len(fhs) == 0 {
		return true
	}
	maxBytes, err := parseByteSize(fl.Param())
	if err != nil || maxBytes <= 0 {
		return true
	}
	for _, fh := range fhs {
		if fh != nil && fh.Size > maxBytes {
			return false
		}
	}
	return true
}

func validateFileMin(fl validator.FieldLevel) bool {
	fhs := extractFileHeaders(fl)
	if len(fhs) == 0 {
		return true
	}
	minBytes, err := parseByteSize(fl.Param())
	if err != nil || minBytes <= 0 {
		return true
	}
	for _, fh := range fhs {
		if fh != nil && fh.Size < minBytes {
			return false
		}
	}
	return true
}

func validateFileExt(fl validator.FieldLevel) bool {
	fhs := extractFileHeaders(fl)
	if len(fhs) == 0 {
		return true
	}
	param := fl.Param()
	if param == "" {
		return true
	}
	allowedList := strings.FieldsFunc(param, func(r rune) bool {
		return r == ';' || r == ',' || r == '|'
	})
	allowedMap := make(map[string]bool, len(allowedList))
	for _, a := range allowedList {
		a = strings.ToLower(strings.TrimSpace(a))
		if a != "" && !strings.HasPrefix(a, ".") {
			a = "." + a
		}
		allowedMap[a] = true
	}

	for _, fh := range fhs {
		if fh == nil {
			continue
		}
		ext := strings.ToLower(filepath.Ext(fh.Filename))
		if !allowedMap[ext] {
			return false
		}
	}
	return true
}

func validateFileMIME(fl validator.FieldLevel) bool {
	fhs := extractFileHeaders(fl)
	if len(fhs) == 0 {
		return true
	}
	param := fl.Param()
	if param == "" {
		return true
	}
	allowedList := strings.FieldsFunc(param, func(r rune) bool {
		return r == ';' || r == ',' || r == '|'
	})

	for _, fh := range fhs {
		if fh == nil {
			continue
		}
		f, err := fh.Open()
		if err != nil {
			return false
		}
		buf := make([]byte, 4096)
		n, _ := f.Read(buf)
		_ = f.Close()

		mtype := mimetype.Detect(buf[:n])
		detectedMIME := mtype.String()

		matched := false
		for _, a := range allowedList {
			a = strings.TrimSpace(a)
			if strings.EqualFold(detectedMIME, a) || mtype.Is(a) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func validateFileImage(fl validator.FieldLevel) bool {
	fhs := extractFileHeaders(fl)
	if len(fhs) == 0 {
		return true
	}
	param := fl.Param()
	parts := strings.Split(strings.ToLower(param), "x")
	if len(parts) != 2 {
		return true
	}
	maxW, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	maxH, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || maxW <= 0 || maxH <= 0 {
		return true
	}

	for _, fh := range fhs {
		if fh == nil {
			continue
		}
		f, err := fh.Open()
		if err != nil {
			return false
		}
		cfg, _, err := image.DecodeConfig(f)
		_ = f.Close()
		if err != nil {
			return false
		}
		if cfg.Width > maxW || cfg.Height > maxH {
			return false
		}
	}
	return true
}

func extractFileHeaders(fl validator.FieldLevel) []*multipart.FileHeader {
	val := fl.Field()
	if !val.IsValid() {
		return nil
	}

	if fh, ok := val.Interface().(*multipart.FileHeader); ok {
		if fh == nil {
			return nil
		}
		return []*multipart.FileHeader{fh}
	}

	if fh, ok := val.Interface().(multipart.FileHeader); ok {
		return []*multipart.FileHeader{&fh}
	}

	if fhs, ok := val.Interface().([]*multipart.FileHeader); ok {
		return fhs
	}

	if fhs, ok := val.Interface().([]multipart.FileHeader); ok {
		res := make([]*multipart.FileHeader, len(fhs))
		for i := range fhs {
			res[i] = &fhs[i]
		}
		return res
	}

	return nil
}

func parseByteSize(s string) (int64, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if s == "" {
		return 0, strconv.ErrSyntax
	}

	var multiplier int64 = 1
	switch {
	case strings.HasSuffix(s, "GB") || strings.HasSuffix(s, "G"):
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "GB"), "G")
	case strings.HasSuffix(s, "MB") || strings.HasSuffix(s, "M"):
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "MB"), "M")
	case strings.HasSuffix(s, "KB") || strings.HasSuffix(s, "K"):
		multiplier = 1024
		s = strings.TrimSuffix(strings.TrimSuffix(s, "KB"), "K")
	case strings.HasSuffix(s, "B"):
		multiplier = 1
		s = strings.TrimSuffix(s, "B")
	}

	val, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, err
	}
	return val * multiplier, nil
}

