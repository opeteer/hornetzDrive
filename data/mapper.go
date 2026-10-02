package data

import (
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"unicode"

	"ztatic-go-framework/security/crypto"
)

var metadataCache sync.Map

// FieldInfo contains reflection metadata for a single struct field.
type FieldInfo struct {
	Name            string
	ColumnName      string
	IndexPath       []int
	Type            reflect.Type
	IsPrimaryKey    bool
	IsAutoIncrement bool
	IsReadOnly      bool
	IsEncrypted     bool
}

// StructMetadata caches reflection inspection results for a given struct type.
type StructMetadata struct {
	Type            reflect.Type
	TableName       string
	Columns         []string
	Fields          []FieldInfo
	FieldByColumn   map[string]FieldInfo
	PrimaryKeyCol   string
	PrimaryKeyField *FieldInfo
	HasEncryption   bool
}

// GetMetadata retrieves or builds cached reflection metadata for type T.
func GetMetadata[T any]() *StructMetadata {
	var zero T
	t := reflect.TypeOf(zero)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return GetMetadataForType(t)
}

// GetMetadataForType retrieves or builds cached reflection metadata for a reflect.Type.
func GetMetadataForType(t reflect.Type) *StructMetadata {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return &StructMetadata{
			Type:          t,
			FieldByColumn: make(map[string]FieldInfo),
		}
	}

	if val, ok := metadataCache.Load(t); ok {
		return val.(*StructMetadata)
	}

	meta := buildMetadata(t)
	metadataCache.Store(t, meta)
	return meta
}

func buildMetadata(t reflect.Type) *StructMetadata {
	meta := &StructMetadata{
		Type:          t,
		FieldByColumn: make(map[string]FieldInfo),
	}

	inspectFields(t, nil, meta)

	// If no primary key was explicitly marked with db:",primarykey",
	// look for fields named ID, Id, or column "id".
	if meta.PrimaryKeyField == nil {
		if fi, ok := meta.FieldByColumn["id"]; ok {
			fi.IsPrimaryKey = true
			if isIntegerKind(fi.Type.Kind()) {
				fi.IsAutoIncrement = true
			}
			meta.FieldByColumn["id"] = fi
			meta.PrimaryKeyCol = "id"
			meta.PrimaryKeyField = &fi
		} else {
			for i, fi := range meta.Fields {
				if strings.EqualFold(fi.Name, "id") {
					meta.Fields[i].IsPrimaryKey = true
					if isIntegerKind(fi.Type.Kind()) {
						meta.Fields[i].IsAutoIncrement = true
					}
					fiCopy := meta.Fields[i]
					meta.FieldByColumn[fi.ColumnName] = fiCopy
					meta.PrimaryKeyCol = fi.ColumnName
					meta.PrimaryKeyField = &fiCopy
					break
				}
			}
		}
	}

	return meta
}

func inspectFields(t reflect.Type, parentIndices []int, meta *StructMetadata) {
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}

		currentPath := append(append([]int(nil), parentIndices...), i)

		// Handle embedded anonymous structs
		if field.Anonymous {
			fieldType := field.Type
			for fieldType.Kind() == reflect.Pointer {
				fieldType = fieldType.Elem()
			}
			if fieldType.Kind() == reflect.Struct {
				dbTag := field.Tag.Get("db")
				if dbTag != "-" {
					inspectFields(fieldType, currentPath, meta)
					continue
				}
			}
		}

		dbTag := field.Tag.Get("db")
		if dbTag == "-" {
			continue
		}

		colName, options := parseTag(dbTag)
		if colName == "" {
			// Fall back to json tag, or to snake_case of field name
			jsonTag := field.Tag.Get("json")
			jsonName, _ := parseTag(jsonTag)
			if jsonName != "" && jsonName != "-" {
				colName = jsonName
			} else {
				colName = toSnakeCase(field.Name)
			}
		}

		isPK := false
		isAuto := false
		isReadOnly := false
		for _, opt := range options {
			switch strings.ToLower(opt) {
			case "primarykey", "pk":
				isPK = true
				if isIntegerKind(field.Type.Kind()) {
					isAuto = true
				}
			case "autoincrement", "auto":
				isAuto = true
			case "readonly":
				isReadOnly = true
			}
		}

		isEncrypted := false
		if field.Tag.Get("ztatic") == "encrypt" {
			isEncrypted = true
			meta.HasEncryption = true
		}

		fi := FieldInfo{
			Name:            field.Name,
			ColumnName:      colName,
			IndexPath:       currentPath,
			Type:            field.Type,
			IsPrimaryKey:    isPK,
			IsAutoIncrement: isAuto,
			IsReadOnly:      isReadOnly,
			IsEncrypted:     isEncrypted,
		}

		meta.Columns = append(meta.Columns, colName)
		meta.Fields = append(meta.Fields, fi)
		meta.FieldByColumn[colName] = fi

		if isPK {
			meta.PrimaryKeyCol = colName
			meta.PrimaryKeyField = &fi
		}
	}
}

func parseTag(tag string) (string, []string) {
	if tag == "" {
		return "", nil
	}
	parts := strings.Split(tag, ",")
	name := strings.TrimSpace(parts[0])
	var opts []string
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		if p != "" {
			opts = append(opts, p)
		}
	}
	return name, opts
}

func isIntegerKind(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	default:
		return false
	}
}

func toSnakeCase(s string) string {
	var b strings.Builder
	for i, r := range s {
		if unicode.IsUpper(r) {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// resolveFieldPtr traverses IndexPath on structVal and returns a pointer to the target field.
func resolveFieldPtr(structVal reflect.Value, indexPath []int) reflect.Value {
	v := structVal
	for _, idx := range indexPath {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		}
		v = v.Field(idx)
	}
	return v.Addr()
}

// ScanOne maps a single database row into a new struct pointer of type T.
func ScanOne[T any](row Scanner, meta *StructMetadata) (*T, error) {
	if meta == nil {
		meta = GetMetadata[T]()
	}

	var entity T
	entityVal := reflect.ValueOf(&entity).Elem()

	// If row provides Columns() (e.g., from *sql.Rows)
	if colScanner, ok := row.(interface{ Columns() ([]string, error) }); ok {
		cols, err := colScanner.Columns()
		if err != nil {
			return nil, err
		}
		dest := make([]any, len(cols))
		var discard any
		for i, col := range cols {
			if fi, exists := meta.FieldByColumn[col]; exists {
				dest[i] = resolveFieldPtr(entityVal, fi.IndexPath).Interface()
			} else {
				dest[i] = &discard
			}
		}
		if err := row.Scan(dest...); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	} else {
		// Fallback for *sql.Row where Columns() is not exposed:
		// scan in the exact order of meta.Columns.
		dest := make([]any, len(meta.Fields))
		for i, fi := range meta.Fields {
			dest[i] = resolveFieldPtr(entityVal, fi.IndexPath).Interface()
		}
		if err := row.Scan(dest...); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, ErrNotFound
			}
			return nil, err
		}
	}

	// Automatic decryption if model has encrypted fields
	if meta.HasEncryption {
		cs := crypto.GetDefaultCipherSuite()
		if cs != nil {
			_ = crypto.ProcessStruct(&entity, cs, false)
		}
	}

	return &entity, nil
}

// ScanAll maps all rows from a *sql.Rows result into a slice of T.
func ScanAll[T any](rows *sql.Rows, meta *StructMetadata) ([]T, error) {
	if meta == nil {
		meta = GetMetadata[T]()
	}

	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}

	// Pre-resolve field index paths for the returned columns
	type colBinding struct {
		isMapped  bool
		indexPath []int
	}
	bindings := make([]colBinding, len(cols))
	for i, col := range cols {
		if fi, exists := meta.FieldByColumn[col]; exists {
			bindings[i] = colBinding{isMapped: true, indexPath: fi.IndexPath}
		}
	}

	items := make([]T, 0)
	var discard any

	cs := crypto.GetDefaultCipherSuite()

	for rows.Next() {
		var item T
		itemVal := reflect.ValueOf(&item).Elem()

		scanTargets := make([]any, len(cols))
		for i, binding := range bindings {
			if binding.isMapped {
				scanTargets[i] = resolveFieldPtr(itemVal, binding.indexPath).Interface()
			} else {
				scanTargets[i] = &discard
			}
		}

		if err := rows.Scan(scanTargets...); err != nil {
			return nil, err
		}

		if meta.HasEncryption && cs != nil {
			_ = crypto.ProcessStruct(&item, cs, false)
		}

		items = append(items, item)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return items, nil
}

// ExtractValues extracts column names and parameter values from a struct instance.
// When forInsert is true, auto-increment primary keys with zero values are omitted.
// When forInsert is false (for update), primary key and readonly columns are omitted.
func ExtractValues(entity any, meta *StructMetadata, forInsert bool) ([]string, []any, error) {
	val := reflect.ValueOf(entity)
	for val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil, nil, errors.New("ztatic/data: cannot extract values from nil pointer")
		}
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil, nil, errors.New("ztatic/data: expected struct entity")
	}

	if meta == nil {
		meta = GetMetadataForType(val.Type())
	}

	var cols []string
	var vals []any

	cs := crypto.GetDefaultCipherSuite()

	for _, fi := range meta.Fields {
		if forInsert {
			// Skip auto-increment PK if zero
			if fi.IsPrimaryKey && fi.IsAutoIncrement {
				fieldVal := getFieldValue(val, fi.IndexPath)
				if isZero(fieldVal) {
					continue
				}
			}
		} else {
			// Skip primary key and readonly fields on update
			if fi.IsPrimaryKey || fi.IsReadOnly {
				continue
			}
		}

		fieldVal := getFieldValue(val, fi.IndexPath)
		var v any = fieldVal.Interface()

		// If field is marked for encryption, encrypt string value
		if fi.IsEncrypted && cs != nil {
			if str, ok := v.(string); ok && str != "" {
				if encrypted, err := cs.Encrypt(str); err == nil {
					v = encrypted
				}
			}
		}

		cols = append(cols, fi.ColumnName)
		vals = append(vals, v)
	}

	return cols, vals, nil
}

func getFieldValue(structVal reflect.Value, indexPath []int) reflect.Value {
	v := structVal
	for _, idx := range indexPath {
		if v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return reflect.Zero(v.Type().Elem())
			}
			v = v.Elem()
		}
		v = v.Field(idx)
	}
	return v
}

func isZero(v reflect.Value) bool {
	if !v.IsValid() {
		return true
	}
	return v.IsZero()
}

// SetPrimaryKeyValue sets the primary key value on an entity struct pointer.
func SetPrimaryKeyValue(entity any, meta *StructMetadata, idVal any) error {
	val := reflect.ValueOf(entity)
	if val.Kind() != reflect.Pointer || val.IsNil() {
		return errors.New("ztatic/data: entity must be a non-nil pointer")
	}
	val = val.Elem()

	if meta == nil || meta.PrimaryKeyField == nil {
		return errors.New("ztatic/data: no primary key field found in metadata")
	}

	targetField := resolveFieldPtr(val, meta.PrimaryKeyField.IndexPath).Elem()
	if !targetField.CanSet() {
		return errors.New("ztatic/data: primary key field cannot be set")
	}

	idReflectVal := reflect.ValueOf(idVal)
	if idReflectVal.Type().ConvertibleTo(targetField.Type()) {
		targetField.Set(idReflectVal.Convert(targetField.Type()))
		return nil
	}

	return fmt.Errorf("ztatic/data: cannot convert id of type %s to primary key type %s", idReflectVal.Type(), targetField.Type())
}

// GetPrimaryKeyValue extracts the primary key value from an entity.
func GetPrimaryKeyValue(entity any, meta *StructMetadata) (any, error) {
	val := reflect.ValueOf(entity)
	for val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil, errors.New("ztatic/data: nil entity")
		}
		val = val.Elem()
	}

	if meta == nil || meta.PrimaryKeyField == nil {
		return nil, errors.New("ztatic/data: no primary key field found in metadata")
	}

	fieldVal := getFieldValue(val, meta.PrimaryKeyField.IndexPath)
	return fieldVal.Interface(), nil
}
