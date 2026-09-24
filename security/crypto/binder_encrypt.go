package crypto

import (
	"errors"
	"reflect"
	"strings"
)

const ztaticTag = "ztatic"

var (
	ErrUnaddressableSlice = errors.New("ztatic/crypto: slice items must be pointers or addressable (use []*Struct or &[]Struct) for field encryption")
)

// ProcessStruct recursively traverses a data structure (passed by pointer) and
// encrypts or decrypts all string fields that are tagged with `ztatic:"encrypt"`.
func ProcessStruct(data any, cs *CipherSuite, isEncrypting bool) error {
	v := reflect.ValueOf(data)
	if !v.IsValid() || v.IsNil() {
		return nil
	}

	// If a pointer, dereference top-level pointer
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}

	return processValue(v, cs, isEncrypting)
}

func processValue(v reflect.Value, cs *CipherSuite, isEncrypting bool) error {
	if !v.IsValid() {
		return nil
	}

	// Handle pointers by dereferencing them
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		return processValue(v.Elem(), cs, isEncrypting)
	}

	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			fieldVal := v.Field(i)
			fieldType := t.Field(i)

			// Recurse into nested structs, pointers, slices
			if fieldVal.Kind() == reflect.Struct || fieldVal.Kind() == reflect.Ptr || fieldVal.Kind() == reflect.Slice || fieldVal.Kind() == reflect.Array {
				if err := processValue(fieldVal, cs, isEncrypting); err != nil {
					return err
				}
				continue
			}

			// Check for ztatic tag
			tagValue := fieldType.Tag.Get(ztaticTag)
			if strings.Contains(tagValue, "encrypt") && fieldVal.Kind() == reflect.String {
				if !fieldVal.CanSet() {
					return ErrUnaddressableSlice
				}

				currentStr := fieldVal.String()
				if currentStr == "" {
					continue
				}

				var processedStr string
				var err error

				if isEncrypting {
					processedStr, err = cs.Encrypt(currentStr)
				} else {
					processedStr, err = cs.Decrypt(currentStr)
				}

				if err != nil {
					return err
				}
				fieldVal.SetString(processedStr)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)

			// If slice element is not a pointer and unaddressable, return explicit error
			if elem.Kind() != reflect.Ptr && !elem.CanSet() {
				// Check if this struct actually contains fields with ztatic:"encrypt"
				if containsEncryptTag(elem) {
					return ErrUnaddressableSlice
				}
			}

			if err := processValue(elem, cs, isEncrypting); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsEncryptTag(v reflect.Value) bool {
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return false
	}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		tagValue := t.Field(i).Tag.Get(ztaticTag)
		if strings.Contains(tagValue, "encrypt") {
			return true
		}
	}
	return false
}
