package data

import (
	"context"
	"errors"
	"testing"
)

func TestTransaction_AmbientContext(t *testing.T) {
	db, err := NewDBEngine("dummy", "test-dsn")
	if err != nil {
		t.Fatalf("failed to open dummy db: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 1. Outside transaction: GetExecutor returns db.SQL
	exec := db.GetExecutor(ctx)
	if exec != db.SQL {
		t.Errorf("expected GetExecutor outside tx to return db.SQL")
	}

	// 2. Inside transaction: GetExecutor returns *sql.Tx
	var txSeenInside bool
	err = db.TransactionCtx(ctx, func(txCtx context.Context) error {
		tx := TxFromContext(txCtx)
		if tx == nil {
			t.Errorf("expected TxFromContext to return active transaction")
		}
		execInside := db.GetExecutor(txCtx)
		if execInside == db.SQL {
			t.Errorf("expected GetExecutor inside tx to return *sql.Tx, not db.SQL")
		}
		txSeenInside = true
		return nil
	})

	if err != nil {
		t.Fatalf("TransactionCtx failed: %v", err)
	}
	if !txSeenInside {
		t.Errorf("transaction callback was not executed")
	}

	// 3. Rollback on error
	expectedErr := errors.New("business error rollback")
	err = db.TransactionCtx(ctx, func(txCtx context.Context) error {
		return expectedErr
	})
	if !errors.Is(err, expectedErr) {
		t.Errorf("expected %v, got %v", expectedErr, err)
	}

	// 4. Nested transaction via savepoint
	err = db.TransactionCtx(ctx, func(txCtx context.Context) error {
		// Nested transaction should create savepoint and succeed
		nestedErr := db.TransactionCtx(txCtx, func(nestedCtx context.Context) error {
			return nil
		})
		if nestedErr != nil {
			return nestedErr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("nested transaction failed: %v", err)
	}
}

func TestTransaction_PanicRecovery(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	ctx := context.Background()

	defer func() {
		if p := recover(); p == nil {
			t.Errorf("expected panic to be re-thrown after rollback")
		}
	}()

	_ = db.TransactionCtx(ctx, func(txCtx context.Context) error {
		panic("simulated panic in transaction")
	})
}
