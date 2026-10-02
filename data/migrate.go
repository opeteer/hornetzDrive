package data

import (
	"database/sql"
	"fmt"
	"io/fs"

	"github.com/pressly/goose/v3"
)

// MigrationEngine handles safe, version-controlled database schema migrations.
// It is designed to read .sql migration files directly from a Go 1.16+ embed.FS,
// allowing migrations to be compiled directly into the deployment binary.
type MigrationEngine struct {
	db *sql.DB
}

// NewMigrationEngine initializes the schema migration runner.
func NewMigrationEngine(db *sql.DB) *MigrationEngine {
	return &MigrationEngine{db: db}
}

// RunMigrations applies all pending schema migrations found in the embedded filesystem.
func (m *MigrationEngine) RunMigrations(fileSystem fs.FS, dir string, dialect string) error {
	goose.SetBaseFS(fileSystem)
	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("ztatic/data: failed to set dialect %s: %w", dialect, err)
	}
	if err := goose.Up(m.db, dir); err != nil {
		return fmt.Errorf("ztatic/data: failed to run migrations: %w", err)
	}
	return nil
}

// Rollback reverts the most recently applied migration (Goose Down).
func (m *MigrationEngine) Rollback(fileSystem fs.FS, dir string, dialect string) error {
	goose.SetBaseFS(fileSystem)
	if err := goose.SetDialect(dialect); err != nil {
		return fmt.Errorf("ztatic/data: failed to set dialect %s: %w", dialect, err)
	}
	if err := goose.Down(m.db, dir); err != nil {
		return fmt.Errorf("ztatic/data: failed to rollback migration: %w", err)
	}
	return nil
}
