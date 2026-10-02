package data

import (
	"context"
	"database/sql"
	"fmt"
	"sync/atomic"
)

// DBExecutor abstracts database query execution across *sql.DB and *sql.Tx.
type DBExecutor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type txContextKey struct{}

var savepointSeq int64

// WithTx embeds an active database transaction into the context.
func WithTx(ctx context.Context, tx *sql.Tx) context.Context {
	if tx == nil || ctx == nil {
		return ctx
	}
	return context.WithValue(ctx, txContextKey{}, tx)
}

// TxFromContext extracts an active database transaction from the context, or returns nil.
func TxFromContext(ctx context.Context) *sql.Tx {
	if ctx == nil {
		return nil
	}
	if tx, ok := ctx.Value(txContextKey{}).(*sql.Tx); ok {
		return tx
	}
	return nil
}

// WithTransaction runs the given function within an ACID transaction.
// If an ambient transaction already exists in ctx, it creates a nested savepoint.
// Otherwise, it starts a new transaction, commits upon success, and rolls back on error or panic.
func WithTransaction(ctx context.Context, db *DBEngine, fn func(txCtx context.Context) error) error {
	if db == nil || db.SQL == nil {
		return fmt.Errorf("ztatic/data: uninitialized DBEngine")
	}

	// 1. If already within an active transaction, handle via SAVEPOINT
	if parentTx := TxFromContext(ctx); parentTx != nil {
		spID := atomic.AddInt64(&savepointSeq, 1)
		spName := fmt.Sprintf("sp_ztatic_%d", spID)

		if err := Savepoint(ctx, spName); err != nil {
			return fmt.Errorf("ztatic/data: failed to create savepoint %s: %w", spName, err)
		}

		defer func() {
			if p := recover(); p != nil {
				_ = RollbackTo(ctx, spName)
				panic(p)
			}
		}()

		if err := fn(ctx); err != nil {
			_ = RollbackTo(ctx, spName)
			return err
		}

		if err := ReleaseSavepoint(ctx, spName); err != nil {
			// Some drivers (e.g. older MySQL) don't strictly require release, ignore error if release fails
			return nil
		}
		return nil
	}

	// 2. Start a new transaction
	tx, err := db.SQL.BeginTx(ctx, nil)
	if err != nil {
		return err
	}

	defer func() {
		if p := recover(); p != nil {
			_ = tx.Rollback()
			panic(p)
		}
	}()

	txCtx := WithTx(ctx, tx)
	if err := fn(txCtx); err != nil {
		_ = tx.Rollback()
		return err
	}

	return tx.Commit()
}

// Savepoint establishes a database savepoint within the active transaction.
func Savepoint(ctx context.Context, name string) error {
	tx := TxFromContext(ctx)
	if tx == nil {
		return fmt.Errorf("ztatic/data: no active transaction in context for savepoint")
	}
	clean := cleanIdentifier(name)
	if clean == "" {
		return fmt.Errorf("ztatic/data: invalid savepoint name")
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("SAVEPOINT %s", clean))
	return err
}

// RollbackTo rolls back the active transaction to the designated savepoint.
func RollbackTo(ctx context.Context, name string) error {
	tx := TxFromContext(ctx)
	if tx == nil {
		return fmt.Errorf("ztatic/data: no active transaction in context for savepoint rollback")
	}
	clean := cleanIdentifier(name)
	if clean == "" {
		return fmt.Errorf("ztatic/data: invalid savepoint name")
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("ROLLBACK TO %s", clean))
	return err
}

// ReleaseSavepoint disposes of the designated savepoint.
func ReleaseSavepoint(ctx context.Context, name string) error {
	tx := TxFromContext(ctx)
	if tx == nil {
		return fmt.Errorf("ztatic/data: no active transaction in context for savepoint release")
	}
	clean := cleanIdentifier(name)
	if clean == "" {
		return fmt.Errorf("ztatic/data: invalid savepoint name")
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf("RELEASE SAVEPOINT %s", clean))
	return err
}
