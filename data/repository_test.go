package data

import (
	"context"
	"testing"
)

type User struct {
	ID   int
	Name string
}

func TestBaseRepository_API(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()

	repo := NewBaseRepository[User](db, "users")

	// Verify generic struct initialization
	if repo.TableName != "users" {
		t.Errorf("Expected table name 'users', got %s", repo.TableName)
	}

	// We won't execute FindByID because the dummy driver returns nil rows,
	// which sql.DB rejects with an error before hitting our code.
	// But we can test the DeleteByID wrapper which uses Exec().
	ctx := context.Background()
	err := repo.DeleteByID(ctx, 1)
	if err != nil {
		t.Errorf("DeleteByID failed: %v", err)
	}
}
