package data

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"testing"
)

// --- Dummy SQL Driver for Sandbox Testing ---
type dummyDriver struct{}

func (d dummyDriver) Open(name string) (driver.Conn, error) {
	return &dummyConn{}, nil
}

type dummyConn struct{}

func (c *dummyConn) Prepare(query string) (driver.Stmt, error) { return &dummyStmt{}, nil }
func (c *dummyConn) Close() error                              { return nil }
func (c *dummyConn) Begin() (driver.Tx, error)                 { return &dummyTx{}, nil }

func (c *dummyConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	return &dummyTx{}, nil
}

func (c *dummyConn) Ping(ctx context.Context) error { return nil }

type dummyTx struct{}

func (t *dummyTx) Commit() error   { return nil }
func (t *dummyTx) Rollback() error { return nil }

type dummyStmt struct{}

func (s *dummyStmt) Close() error                                    { return nil }
func (s *dummyStmt) NumInput() int                                   { return -1 }
func (s *dummyStmt) Exec(args []driver.Value) (driver.Result, error) { return &dummyResult{}, nil }
func (s *dummyStmt) Query(args []driver.Value) (driver.Rows, error)  { return &dummyRows{}, nil }

type dummyRows struct{}

func (r *dummyRows) Columns() []string              { return []string{"id"} }
func (r *dummyRows) Close() error                   { return nil }
func (r *dummyRows) Next(dest []driver.Value) error { return io.EOF }

type dummyResult struct{}

func (r *dummyResult) LastInsertId() (int64, error) { return 1, nil }
func (r *dummyResult) RowsAffected() (int64, error) { return 1, nil }

func init() {
	sql.Register("dummy", dummyDriver{})
}

func TestDBEngine_InitAndClose(t *testing.T) {
	db, err := NewDBEngine("dummy", "test-dsn")
	if err != nil {
		t.Fatalf("Failed to initialize DBEngine: %v", err)
	}
	err = db.Close()
	if err != nil {
		t.Fatalf("Failed to close DBEngine: %v", err)
	}
}

func TestDBEngine_TransactionSuccess(t *testing.T) {
	db, _ := NewDBEngine("dummy", "test-dsn")
	defer db.Close()
	ctx := context.Background()
	err := db.Transaction(ctx, func(tx *sql.Tx) error { return nil })
	if err != nil {
		t.Fatalf("Transaction failed unexpectedly: %v", err)
	}
}

func TestMigrationEngine_Run(t *testing.T) {
	// Skip goose up since dummy driver isn't fully mocked for goose schema inspection
	t.Skip("Skipping goose migration with dummy driver")
}

func TestDBEngine_Rebind(t *testing.T) {
	pgEngine := &DBEngine{DriverName: "postgres"}
	sqliteEngine := &DBEngine{DriverName: "sqlite3"}

	query := "INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES (?, 1, ?, ?, ?, ?, ?)"
	
	pgRebound := pgEngine.Rebind(query)
	expectedPg := "INSERT INTO files (id, owner_id, folder_id, name, mime_type, size, cas_hash) VALUES ($1, 1, $2, $3, $4, $5, $6)"
	if pgRebound != expectedPg {
		t.Fatalf("Expected Postgres rebound query:\n%s\nGot:\n%s", expectedPg, pgRebound)
	}

	sqliteRebound := sqliteEngine.Rebind(query)
	if sqliteRebound != query {
		t.Fatalf("Expected SQLite query to remain unchanged:\n%s\nGot:\n%s", query, sqliteRebound)
	}
}
