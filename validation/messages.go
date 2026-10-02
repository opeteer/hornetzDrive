package validation

import (
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
)

var defaultRuleTemplates = map[string]string{
	"required":         "Field '{field}' is required",
	"email":            "Field '{field}' must be a valid email address",
	"min":              "Field '{field}' must be at least {param} in length or value",
	"max":              "Field '{field}' must be at most {param} in length or value",
	"len":              "Field '{field}' must be exactly {param} in length",
	"alphanum":         "Field '{field}' must be alphanumeric",
	"url":              "Field '{field}' must be a valid URL",
	"uuid":             "Field '{field}' must be a valid UUID",
	"strong_password":  "Field '{field}' must be at least {param} characters and include uppercase, lowercase, numbers, and symbols",
	"no_html":          "Field '{field}' must not contain HTML or script markup",
	"xss_safe":         "Field '{field}' contains hazardous script or HTML tags",
	"no_sql_injection": "Field '{field}' contains forbidden SQL injection syntax",
	"safe_path":        "Field '{field}' contains invalid path or directory traversal characters",
	"slug":             "Field '{field}' must be a valid kebab-case slug",
	"phone":            "Field '{field}' must be a valid international phone number",
	"semver":           "Field '{field}' must be a valid semantic version",
	"cron":             "Field '{field}' must be a valid 5-field cron expression",
	"json":             "Field '{field}' must be a valid JSON string",
	"credit_card":      "Field '{field}' must be a valid credit card number",
	"unique":           "Field '{field}' already exists",
	"exists":           "Field '{field}' does not exist",
	"file_max":         "Field '{field}' file size exceeds maximum allowed of {param}",
	"file_min":         "Field '{field}' file size is smaller than minimum required of {param}",
	"file_ext":         "Field '{field}' has an invalid file extension (allowed: {param})",
	"file_mime":        "Field '{field}' has an unsupported file MIME type (allowed: {param})",
	"file_image":       "Field '{field}' image dimensions exceed allowed limits of {param}",
}

var (
	msgRegistryMu       sync.RWMutex
	globalRuleMessages  = make(map[string]string)
	globalFieldMessages = make(map[string]string)
)

// RegisterRuleMessage registers a global custom message template for a validation rule.
// Supported tokens: {field}, {rule}, {tag}, {param}, {value}.
func RegisterRuleMessage(rule, template string) {
	msgRegistryMu.Lock()
	defer msgRegistryMu.Unlock()
	globalRuleMessages[rule] = template
}

// RegisterFieldMessage registers a global custom message for a specific field and rule.
// e.g. RegisterFieldMessage("email", "required", "Email is required to activate your account.")
func RegisterFieldMessage(field, rule, template string) {
	msgRegistryMu.Lock()
	defer msgRegistryMu.Unlock()
	globalFieldMessages[field+"."+rule] = template
}

// Interpolate replaces placeholder tokens in a message template.
func Interpolate(tmpl, field, rule, param string, value any) string {
	valStr := ""
	if value != nil {
		valStr = fmt.Sprint(value)
	}

	p := param
	if p == "" && rule == "strong_password" {
		p = "8"
	}

	res := tmpl
	res = strings.ReplaceAll(res, "{field}", field)
	res = strings.ReplaceAll(res, "{rule}", rule)
	res = strings.ReplaceAll(res, "{tag}", rule)
	res = strings.ReplaceAll(res, "{param}", p)
	res = strings.ReplaceAll(res, "{value}", valStr)
	return res
}

// ExtractStructTagMessages inspects a struct (and embedded structs) via reflection
// to extract custom messages declared via `message` or `msg` struct tags.
// Key format: map[fieldName]map[ruleName]message, where ruleName="*" is the wildcard fallback.
func ExtractStructTagMessages(i any) map[string]map[string]string {
	result := make(map[string]map[string]string)
	if i == nil {
		return result
	}

	val := reflect.ValueOf(i)
	for val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return result
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return result
	}

	extractStructTypeMessages(val.Type(), result)
	return result
}

func extractStructTypeMessages(t reflect.Type, result map[string]map[string]string) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)

		// Recursively extract embedded structs
		if field.Anonymous {
			fieldType := field.Type
			for fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.Struct {
				extractStructTypeMessages(fieldType, result)
			}
			continue
		}

		tag := field.Tag.Get("message")
		if tag == "" {
			tag = field.Tag.Get("msg")
		}

		if tag != "" {
			parsed := parseMessageTag(tag)
			// Associate with struct field name
			result[field.Name] = parsed

			// Also associate with json tag name if specified
			jsonTag := field.Tag.Get("json")
			if jsonTag != "" && jsonTag != "-" {
				jsonName := strings.Split(jsonTag, ",")[0]
				if jsonName != "" {
					result[jsonName] = parsed
				}
			}
		}
	}
}

// parseMessageTag parses a message tag into rule-specific and universal messages.
// Examples:
// - "min=Password too short,required=Password required" -> {"min": "...", "required": "..."}
// - "Please provide a valid email" -> {"*": "Please provide a valid email"}
func parseMessageTag(tag string) map[string]string {
	out := make(map[string]string)
	if !strings.Contains(tag, "=") {
		out["*"] = strings.TrimSpace(tag)
		return out
	}

	pairs := strings.Split(tag, ",")
	for _, pair := range pairs {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 {
			k := strings.TrimSpace(kv[0])
			v := strings.TrimSpace(kv[1])
			if k != "" && v != "" {
				out[k] = v
			}
		}
	}
	return out
}

// ResolveMessage computes the final human-readable error message for a validation error.
func ResolveMessage(tagMsgs map[string]map[string]string, fe validator.FieldError) string {
	structField := fe.StructField()
	field := fe.Field()
	rule := fe.Tag()
	param := fe.Param()
	value := fe.Value()

	// 1. Check struct tag messages for specific rule
	if tagMsgs != nil {
		if msgs, ok := tagMsgs[structField]; ok {
			if msg, exists := msgs[rule]; exists {
				return Interpolate(msg, field, rule, param, value)
			}
			if msg, exists := msgs["*"]; exists {
				return Interpolate(msg, field, rule, param, value)
			}
		}
		if msgs, ok := tagMsgs[field]; ok {
			if msg, exists := msgs[rule]; exists {
				return Interpolate(msg, field, rule, param, value)
			}
			if msg, exists := msgs["*"]; exists {
				return Interpolate(msg, field, rule, param, value)
			}
		}
	}

	msgRegistryMu.RLock()
	defer msgRegistryMu.RUnlock()

	// 2. Check registered field-specific message (e.g. "email.required")
	if tmpl, ok := globalFieldMessages[field+"."+rule]; ok {
		return Interpolate(tmpl, field, rule, param, value)
	}

	// 3. Check registered global rule message (e.g. "min")
	if tmpl, ok := globalRuleMessages[rule]; ok {
		return Interpolate(tmpl, field, rule, param, value)
	}

	// 4. Check built-in default rule template
	if tmpl, ok := defaultRuleTemplates[rule]; ok {
		return Interpolate(tmpl, field, rule, param, value)
	}

	// 5. Generic fallback
	if param != "" {
		return fmt.Sprintf("Field '%s' failed on '%s' rule with parameter '%s'", field, rule, param)
	}
	return fmt.Sprintf("Field '%s' failed on '%s' validation tag", field, rule)
}
