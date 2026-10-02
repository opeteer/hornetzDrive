package data

import (
	"strings"
	"testing"

	"github.com/Masterminds/squirrel"
	"ztatic-go-framework/response"
)

func TestPagination_BuildCountBuilder(t *testing.T) {
	// Standard select query
	base := squirrel.Select("id", "title", "content").
		From("articles").
		Where(squirrel.Eq{"status": "published"}).
		Limit(10).
		Offset(20)

	countB := buildCountBuilder(base)
	sqlStr, args, err := countB.ToSql()
	if err != nil {
		t.Fatalf("ToSql failed: %v", err)
	}

	if !strings.Contains(sqlStr, "SELECT COUNT(*) FROM articles") {
		t.Errorf("expected SELECT COUNT(*) FROM articles, got: %s", sqlStr)
	}
	if strings.Contains(sqlStr, "LIMIT") || strings.Contains(sqlStr, "OFFSET") {
		t.Errorf("expected LIMIT/OFFSET to be stripped from count query: %s", sqlStr)
	}
	if len(args) != 1 {
		t.Errorf("expected 1 arg, got %d", len(args))
	}

	// Query with Group By should wrap as subquery
	grouped := squirrel.Select("category_id", "COUNT(*) as count").
		From("articles").
		GroupBy("category_id")

	countGrouped := buildCountBuilder(grouped)
	groupedSQL, _, err := countGrouped.ToSql()
	if err != nil {
		t.Fatalf("ToSql for grouped failed: %v", err)
	}

	if !strings.Contains(groupedSQL, "count_sub") {
		t.Errorf("expected grouped count to use subquery 'count_sub', got: %s", groupedSQL)
	}
}

func TestPagination_CursorEncodingIntegration(t *testing.T) {
	cursorVal := 42
	encoded, err := response.EncodeCursor(cursorVal)
	if err != nil {
		t.Fatalf("EncodeCursor failed: %v", err)
	}

	decoded, err := response.DecodeCursor[int](encoded)
	if err != nil {
		t.Fatalf("DecodeCursor failed: %v", err)
	}

	if *decoded != 42 {
		t.Errorf("expected decoded cursor to be 42, got %d", *decoded)
	}
}
