package data

import (
	"context"
	"database/sql"
	"errors"
)

// ErrNotFound is returned when a query expects a row but none is found.
var ErrNotFound = errors.New("ztatic/data: record not found")

// Scanner interface allows abstracting sql.Row and sql.Rows
type Scanner interface {
	Scan(dest ...any) error
}

// BaseRepository provides highly-reusable, generic CRUD operations for any data model.
// Utilizing Go 1.18+ Generics, it eliminates boilerplate SQL rewriting for standard tables.
type BaseRepository[T any] struct {
	DB        *DBEngine
	TableName string
}

// NewBaseRepository instantiates a generic repository for the specified SQL table.
func NewBaseRepository[T any](db *DBEngine, tableName string) *BaseRepository[T] {
	return &BaseRepository[T]{
		DB:        db,
		TableName: tableName,
	}
}

// FindByID retrieves a single entity by its primary key (ID).
// It accepts a custom scanFn to map the SQL columns into the generic Struct T.
func (r *BaseRepository[T]) FindByID(ctx context.Context, id any, scanFn func(row Scanner, entity *T) error) (*T, error) {
	// In production with squirrel enabled, this would dynamically build:
	// query, args, _ := r.DB.Builder.Select("*").From(r.TableName).Where(squirrel.Eq{"id": id}).ToSql()

	// Fallback raw query for sandbox (assumes standard ? placeholder)
	query := "SELECT * FROM " + r.TableName + " WHERE id = ?"

	row := r.DB.SQL.QueryRowContext(ctx, query, id)

	var entity T
	err := scanFn(row, &entity)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	return &entity, nil
}

// DeleteByID removes a record by its primary key.
func (r *BaseRepository[T]) DeleteByID(ctx context.Context, id any) error {
	query := "DELETE FROM " + r.TableName + " WHERE id = ?"

	result, err := r.DB.SQL.ExecContext(ctx, query, id)
	if err != nil {
		return err
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rows == 0 {
		return ErrNotFound
	}

	return nil
}
