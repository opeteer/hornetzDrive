package data

import (
	"testing"
	"testing/fstest"
)

func TestMigrationEngine_InvalidDialect(t *testing.T) {
	engine := NewMigrationEngine(nil)
	testFS := fstest.MapFS{
		"00001_create_users.sql": &fstest.MapFile{
			Data: []byte("-- +goose Up\nCREATE TABLE users (id INT);\n-- +goose Down\nDROP TABLE users;"),
		},
	}

	err := engine.RunMigrations(testFS, ".", "invalid_dialect")
	if err == nil {
		t.Errorf("expected error for invalid dialect, got nil")
	}

	err = engine.Rollback(testFS, ".", "invalid_dialect")
	if err == nil {
		t.Errorf("expected error for invalid rollback dialect, got nil")
	}
}

func TestNewMigrationEngine(t *testing.T) {
	engine := NewMigrationEngine(nil)
	if engine == nil {
		t.Fatalf("expected non-nil MigrationEngine")
	}
}
