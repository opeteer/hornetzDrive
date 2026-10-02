package data

import (
	"fmt"
	"strings"

	"github.com/Masterminds/squirrel"
)

// QueryOption is a function that modifies a squirrel.SelectBuilder.
type QueryOption func(b squirrel.SelectBuilder) squirrel.SelectBuilder

// Scope is a reusable query modifier.
type Scope = QueryOption

// ApplyOptions executes a slice of QueryOptions sequentially onto a SelectBuilder.
func ApplyOptions(b squirrel.SelectBuilder, opts []QueryOption) squirrel.SelectBuilder {
	for _, opt := range opts {
		if opt != nil {
			b = opt(b)
		}
	}
	return b
}

// WithScope applies a reusable business scope to the query builder.
func WithScope(scope Scope) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		if scope != nil {
			return scope(b)
		}
		return b
	}
}

// Where adds a raw or custom predicate expression with optional arguments.
func Where(pred any, args ...any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.Where(pred, args...)
	}
}

// WhereEq adds an equality condition (column = value).
func WhereEq(col string, val any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.Eq{clean: val})
	}
}

// WhereNotEq adds an inequality condition (column != value).
func WhereNotEq(col string, val any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.NotEq{clean: val})
	}
}

// WhereIn adds an IN condition (column IN (val1, val2, ...)).
func WhereIn(col string, vals any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.Eq{clean: vals})
	}
}

// WhereNotIn adds a NOT IN condition (column NOT IN (val1, val2, ...)).
func WhereNotIn(col string, vals any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.NotEq{clean: vals})
	}
}

// WhereGt adds a greater-than condition (column > val).
func WhereGt(col string, val any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.Gt{clean: val})
	}
}

// WhereGtOrEq adds a greater-than-or-equal condition (column >= val).
func WhereGtOrEq(col string, val any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.GtOrEq{clean: val})
	}
}

// WhereLt adds a less-than condition (column < val).
func WhereLt(col string, val any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.Lt{clean: val})
	}
}

// WhereLtOrEq adds a less-than-or-equal condition (column <= val).
func WhereLtOrEq(col string, val any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.LtOrEq{clean: val})
	}
}

// WhereLike adds a LIKE condition (column LIKE pattern).
func WhereLike(col string, pattern string) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.Like{clean: pattern})
	}
}

// WhereILike adds a case-insensitive ILIKE condition (PostgreSQL).
func WhereILike(col string, pattern string) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.ILike{clean: pattern})
	}
}

// WhereNull adds an IS NULL condition (column IS NULL).
func WhereNull(col string) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.Eq{clean: nil})
	}
}

// WhereNotNull adds an IS NOT NULL condition (column IS NOT NULL).
func WhereNotNull(col string) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.NotEq{clean: nil})
	}
}

// WhereBetween adds a range condition (column >= min AND column <= max).
func WhereBetween(col string, min, max any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		clean := cleanIdentifier(col)
		if clean == "" {
			return b
		}
		return b.Where(squirrel.And{
			squirrel.GtOrEq{clean: min},
			squirrel.LtOrEq{clean: max},
		})
	}
}

// OrderBy adds sanitized ORDER BY clauses.
func OrderBy(clauses ...string) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		for _, clause := range clauses {
			parts := strings.Fields(clause)
			if len(parts) == 0 {
				continue
			}
			cleanCol := cleanIdentifier(parts[0])
			if cleanCol == "" {
				continue
			}
			dir := "ASC"
			if len(parts) > 1 && strings.EqualFold(parts[1], "DESC") {
				dir = "DESC"
			}
			b = b.OrderBy(fmt.Sprintf("%s %s", cleanCol, dir))
		}
		return b
	}
}

// OrderByAsc adds an ascending order clause for the column.
func OrderByAsc(col string) QueryOption {
	return OrderBy(col + " ASC")
}

// OrderByDesc adds a descending order clause for the column.
func OrderByDesc(col string) QueryOption {
	return OrderBy(col + " DESC")
}

// Limit sets the query LIMIT.
func Limit(limit uint64) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.Limit(limit)
	}
}

// Offset sets the query OFFSET.
func Offset(offset uint64) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.Offset(offset)
	}
}

// Join adds an INNER JOIN clause.
func Join(join string, rest ...any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.Join(join, rest...)
	}
}

// LeftJoin adds a LEFT JOIN clause.
func LeftJoin(join string, rest ...any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.LeftJoin(join, rest...)
	}
}

// RightJoin adds a RIGHT JOIN clause.
func RightJoin(join string, rest ...any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.RightJoin(join, rest...)
	}
}

// GroupBy adds GROUP BY columns.
func GroupBy(groupBys ...string) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		for _, g := range groupBys {
			if clean := cleanIdentifier(g); clean != "" {
				b = b.GroupBy(clean)
			}
		}
		return b
	}
}

// Having adds a HAVING clause.
func Having(pred any, rest ...any) QueryOption {
	return func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		return b.Having(pred, rest...)
	}
}

// cleanIdentifier allows only letters, digits, underscores, and dots to prevent SQL injection in column names.
func cleanIdentifier(s string) string {
	s = strings.TrimSpace(s)
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.') {
			return ""
		}
	}
	return s
}
