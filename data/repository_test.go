package data

import (
	"context"
	"testing"

	"ztatic-go-framework/rapid"
)

type User struct {
	ID   int    `db:"id,primarykey"`
	Name string `db:"name"`
}

func TestBaseRepository_API(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	repo := NewBaseRepository[User](db, "users")

	// Verify generic struct initialization
	if repo.TableName != "users" {
		t.Errorf("Expected table name 'users', got %s", repo.TableName)
	}

	if repo.PrimaryKey != "id" {
		t.Errorf("Expected primary key 'id', got %s", repo.PrimaryKey)
	}

	ctx := context.Background()
	err := repo.DeleteByID(ctx, 1)
	if err != nil {
		t.Errorf("DeleteByID failed: %v", err)
	}
}

func TestBaseRepository_InsertAndUpdate(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	repo := NewBaseRepository[User](db, "users")
	ctx := context.Background()

	// 1. Insert
	u := &User{Name: "Bob"}
	err := repo.Insert(ctx, u)
	if err != nil {
		t.Errorf("Insert failed: %v", err)
	}
	// Dummy driver returns LastInsertId=1
	if u.ID != 1 {
		t.Errorf("expected auto-populated ID 1, got %d", u.ID)
	}

	// 2. InsertMany
	users := []*User{{Name: "Alice"}, {Name: "Charlie"}}
	err = repo.InsertMany(ctx, users)
	if err != nil {
		t.Errorf("InsertMany failed: %v", err)
	}

	// 3. Save / Update
	u.Name = "Bobby"
	err = repo.Save(ctx, u)
	if err != nil {
		t.Errorf("Save failed: %v", err)
	}

	// 4. UpdateColumns
	err = repo.UpdateColumns(ctx, 1, map[string]any{"name": "Robert"})
	if err != nil {
		t.Errorf("UpdateColumns failed: %v", err)
	}
}

func TestBaseRepository_WithTx(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	repo := NewBaseRepository[User](db, "users")
	ctx := context.Background()

	err := db.TransactionCtx(ctx, func(txCtx context.Context) error {
		tx := TxFromContext(txCtx)
		if tx == nil {
			t.Fatalf("expected tx in context")
		}
		txRepo := repo.WithTx(tx)
		if txRepo.Tx != tx {
			t.Errorf("expected txRepo.Tx to match tx")
		}
		// Insert inside transaction
		return txRepo.Insert(txCtx, &User{Name: "InTx"})
	})
	if err != nil {
		t.Fatalf("transaction failed: %v", err)
	}
}

func TestBaseRepository_RapidInterfaces(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	repo := NewBaseRepository[User](db, "users")

	// Compile-time interface verification
	var _ rapid.Resource[User] = repo
	var _ rapid.PaginatedResource[User] = repo

	// Verify SelectBuilder
	sb := repo.SelectBuilder()
	sqlStr, _, err := sb.ToSql()
	if err != nil {
		t.Fatalf("ToSql failed: %v", err)
	}
	if sqlStr != "SELECT id, name FROM users" {
		t.Errorf("expected 'SELECT id, name FROM users', got '%s'", sqlStr)
	}
}
