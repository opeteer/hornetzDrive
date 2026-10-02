package data

import (
	"reflect"
	"testing"
	"time"

	"ztatic-go-framework/security/crypto"
)

type AuditFields struct {
	CreatedAt time.Time `db:"created_at"`
	UpdatedAt time.Time `db:"updated_at"`
}

type TestArticle struct {
	ID        int    `db:"id,primarykey"`
	Title     string `db:"title"`
	Content   string `json:"content"`
	SecretKey string `db:"secret_key" ztatic:"encrypt"`
	Author    string // Fallback to snake_case
	Ignored   string `db:"-"`
	AuditFields
}

func TestMapper_MetadataInspection(t *testing.T) {
	meta := GetMetadata[TestArticle]()
	if meta == nil {
		t.Fatalf("expected non-nil metadata")
	}

	if meta.PrimaryKeyCol != "id" {
		t.Errorf("expected PrimaryKeyCol 'id', got '%s'", meta.PrimaryKeyCol)
	}

	if meta.PrimaryKeyField == nil || !meta.PrimaryKeyField.IsPrimaryKey || !meta.PrimaryKeyField.IsAutoIncrement {
		t.Errorf("expected primary key to be marked as primary and auto-increment")
	}

	// Verify columns list
	expectedCols := map[string]bool{
		"id":         true,
		"title":      true,
		"content":    true,
		"secret_key": true,
		"author":     true,
		"created_at": true,
		"updated_at": true,
	}

	if len(meta.Columns) != len(expectedCols) {
		t.Errorf("expected %d columns, got %d: %v", len(expectedCols), len(meta.Columns), meta.Columns)
	}

	for _, col := range meta.Columns {
		if !expectedCols[col] {
			t.Errorf("unexpected column: %s", col)
		}
	}

	// Verify ignored field is not in columns
	if _, ok := meta.FieldByColumn["ignored"]; ok {
		t.Errorf("expected 'ignored' field to be excluded")
	}

	// Verify embedded struct fields are resolved
	if _, ok := meta.FieldByColumn["created_at"]; !ok {
		t.Errorf("expected embedded 'created_at' field to be mapped")
	}

	// Verify encryption detection
	if !meta.HasEncryption {
		t.Errorf("expected HasEncryption to be true")
	}
}

func TestMapper_ExtractValues(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	cs, err := crypto.NewCipherSuite(key)
	if err != nil {
		t.Fatalf("failed to create cipher suite: %v", err)
	}
	crypto.SetDefaultCipherSuite(cs)

	now := time.Now()
	article := &TestArticle{
		ID:        0, // Zero value, should be omitted for insert
		Title:     "Learning Go",
		Content:   "Advanced data mapping",
		SecretKey: "super-secret-token",
		Author:    "Alice",
		AuditFields: AuditFields{
			CreatedAt: now,
			UpdatedAt: now,
		},
	}

	meta := GetMetadata[TestArticle]()

	// 1. For Insert: ID=0 should be omitted because it's auto-increment
	cols, vals, err := ExtractValues(article, meta, true)
	if err != nil {
		t.Fatalf("ExtractValues for insert failed: %v", err)
	}

	for _, col := range cols {
		if col == "id" {
			t.Errorf("expected 'id' to be omitted on insert with zero value")
		}
	}

	// Verify encrypted secret_key is not raw text
	var secretVal any
	for i, col := range cols {
		if col == "secret_key" {
			secretVal = vals[i]
		}
	}
	if secretVal == "super-secret-token" || secretVal == nil {
		t.Errorf("expected secret_key to be encrypted, got %v", secretVal)
	}

	// 2. For Update: ID should be omitted
	updateCols, _, err := ExtractValues(article, meta, false)
	if err != nil {
		t.Fatalf("ExtractValues for update failed: %v", err)
	}

	for _, col := range updateCols {
		if col == "id" {
			t.Errorf("expected 'id' to be omitted on update")
		}
	}
}

func TestMapper_SetAndGetPrimaryKey(t *testing.T) {
	meta := GetMetadata[TestArticle]()
	article := &TestArticle{ID: 10}

	pkVal, err := GetPrimaryKeyValue(article, meta)
	if err != nil {
		t.Fatalf("GetPrimaryKeyValue failed: %v", err)
	}
	if pkVal != 10 {
		t.Errorf("expected pk 10, got %v", pkVal)
	}

	err = SetPrimaryKeyValue(article, meta, 42)
	if err != nil {
		t.Fatalf("SetPrimaryKeyValue failed: %v", err)
	}
	if article.ID != 42 {
		t.Errorf("expected ID 42, got %d", article.ID)
	}

	// Test int64 conversion (e.g. from sql.Result.LastInsertId)
	err = SetPrimaryKeyValue(article, meta, int64(100))
	if err != nil {
		t.Fatalf("SetPrimaryKeyValue with int64 failed: %v", err)
	}
	if article.ID != 100 {
		t.Errorf("expected ID 100, got %d", article.ID)
	}
}

// MockScanner simulates a database row scanner with Columns() support
type mockRowWithColumns struct {
	columns []string
	values  []any
}

func (m *mockRowWithColumns) Columns() ([]string, error) {
	return m.columns, nil
}

func (m *mockRowWithColumns) Scan(dest ...any) error {
	for i, val := range m.values {
		if i < len(dest) {
			target := reflect.ValueOf(dest[i])
			if target.Kind() == reflect.Pointer && !target.IsNil() {
				valRef := reflect.ValueOf(val)
				if valRef.Type().ConvertibleTo(target.Elem().Type()) {
					target.Elem().Set(valRef.Convert(target.Elem().Type()))
				}
			}
		}
	}
	return nil
}

func TestMapper_ScanOneWithUnmappedColumns(t *testing.T) {
	row := &mockRowWithColumns{
		columns: []string{"id", "title", "content", "extra_db_col"},
		values:  []any{7, "Test Title", "Content Body", "ignored extra value"},
	}

	meta := GetMetadata[TestArticle]()
	item, err := ScanOne[TestArticle](row, meta)
	if err != nil {
		t.Fatalf("ScanOne failed: %v", err)
	}

	if item.ID != 7 {
		t.Errorf("expected ID 7, got %d", item.ID)
	}
	if item.Title != "Test Title" {
		t.Errorf("expected Title 'Test Title', got '%s'", item.Title)
	}
	if item.Content != "Content Body" {
		t.Errorf("expected Content 'Content Body', got '%s'", item.Content)
	}
}
