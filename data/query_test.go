package data

import (
	"strings"
	"testing"

	"github.com/Masterminds/squirrel"
)

func TestQuery_WherePredicates(t *testing.T) {
	b := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Question).
		Select("id", "title").
		From("articles")

	opts := []QueryOption{
		WhereEq("status", "active"),
		WhereIn("category_id", []int{1, 2, 3}),
		WhereGt("views", 100),
		WhereLtOrEq("priority", 5),
		WhereLike("title", "%Go%"),
		WhereNotNull("published_at"),
		WhereBetween("price", 10, 50),
		OrderByDesc("created_at"),
		Limit(25),
		Offset(50),
	}

	b = ApplyOptions(b, opts)
	sqlStr, args, err := b.ToSql()
	if err != nil {
		t.Fatalf("ToSql failed: %v", err)
	}

	if !strings.Contains(sqlStr, "WHERE") {
		t.Errorf("expected SQL to contain WHERE clause: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "LIMIT 25") {
		t.Errorf("expected LIMIT 25: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "OFFSET 50") {
		t.Errorf("expected OFFSET 50: %s", sqlStr)
	}
	if !strings.Contains(sqlStr, "ORDER BY created_at DESC") {
		t.Errorf("expected ORDER BY created_at DESC: %s", sqlStr)
	}

	// Verify args count
	if len(args) < 7 {
		t.Errorf("expected at least 7 args, got %d", len(args))
	}
}

func TestQuery_Scopes(t *testing.T) {
	publishedScope := func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.Where(squirrel.Eq{"published": true})
	}
	tenantScope := func(tenantID string) Scope {
		return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
			return b.Where(squirrel.Eq{"tenant_id": tenantID})
		}
	}

	b := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Dollar).
		Select("*").
		From("documents")

	b = ApplyOptions(b, []QueryOption{
		WithScope(publishedScope),
		WithScope(tenantScope("org_123")),
	})

	sqlStr, args, err := b.ToSql()
	if err != nil {
		t.Fatalf("ToSql failed: %v", err)
	}

	if !strings.Contains(sqlStr, "$1") || !strings.Contains(sqlStr, "$2") {
		t.Errorf("expected PostgreSQL Dollar placeholders: %s", sqlStr)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args, got %d", len(args))
	}
}

func TestQuery_IdentifierSanitization(t *testing.T) {
	b := squirrel.StatementBuilder.PlaceholderFormat(squirrel.Question).
		Select("id").
		From("users")

	// Injection attempt in OrderBy and column name
	opts := []QueryOption{
		WhereEq("id; DROP TABLE users;--", 1),
		OrderBy("created_at; DROP TABLE users;-- DESC"),
	}

	b = ApplyOptions(b, opts)
	sqlStr, _, err := b.ToSql()
	if err != nil {
		t.Fatalf("ToSql failed: %v", err)
	}

	if strings.Contains(sqlStr, "DROP TABLE") {
		t.Errorf("SQL injection detected in generated SQL: %s", sqlStr)
	}
}
