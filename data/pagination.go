package data

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/Masterminds/squirrel"
	"ztatic-go-framework/response"
)

// PaginateSelect executes an offset-paginated query using squirrel.SelectBuilder,
// calculating total count and mapping the resulting rows into []T.
func PaginateSelect[T any](
	ctx context.Context,
	exec DBExecutor,
	builder squirrel.SelectBuilder,
	p response.PageParams,
	meta *StructMetadata,
) ([]T, *response.PaginationMeta, error) {
	if meta == nil {
		meta = GetMetadata[T]()
	}

	// 1. Construct Count Query
	countBuilder := buildCountBuilder(builder)
	countSQL, countArgs, err := countBuilder.ToSql()
	if err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to build count query: %w", err)
	}

	var totalItems int64
	row := exec.QueryRowContext(ctx, countSQL, countArgs...)
	if err := row.Scan(&totalItems); err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to execute count query: %w", err)
	}

	// 2. Apply Pagination Params to Data Query
	dataBuilder := p.Apply(builder)
	dataSQL, dataArgs, err := dataBuilder.ToSql()
	if err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to build data query: %w", err)
	}

	rows, err := exec.QueryContext(ctx, dataSQL, dataArgs...)
	if err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to execute data query: %w", err)
	}

	items, err := ScanAll[T](rows, meta)
	if err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to scan data rows: %w", err)
	}

	paginationMeta := p.WithTotal(totalItems)
	return items, paginationMeta, nil
}

// buildCountBuilder creates an accurate count query from a SelectBuilder.
func buildCountBuilder(builder squirrel.SelectBuilder) squirrel.SelectBuilder {
	cleanBuilder := builder.RemoveLimit().RemoveOffset()
	sqlStr, _, _ := cleanBuilder.ToSql()

	// If query uses GROUP BY or DISTINCT, wrap in subquery to count grouped rows accurately
	upperSQL := strings.ToUpper(sqlStr)
	if strings.Contains(upperSQL, " GROUP BY ") || strings.Contains(upperSQL, "DISTINCT ") {
		return squirrel.Select("COUNT(*)").FromSelect(cleanBuilder, "count_sub")
	}

	return cleanBuilder.RemoveColumns().Columns("COUNT(*)")
}

// PaginateCursorSelect executes a keyset/cursor paginated query using squirrel.SelectBuilder.
func PaginateCursorSelect[T any](
	ctx context.Context,
	exec DBExecutor,
	builder squirrel.SelectBuilder,
	p response.CursorParams,
	cursorCol string,
	meta *StructMetadata,
) ([]T, *response.CursorMeta, error) {
	if meta == nil {
		meta = GetMetadata[T]()
	}

	if cursorCol == "" {
		if meta.PrimaryKeyCol != "" {
			cursorCol = meta.PrimaryKeyCol
		} else {
			cursorCol = "id"
		}
	}
	cleanCol := cleanIdentifier(cursorCol)

	limit := p.Limit
	if limit <= 0 {
		limit = 20
	}

	// Probe limit + 1 to check if there is a next page
	queryBuilder := builder.Limit(uint64(limit + 1))

	isDescending := p.Direction != "prev"

	// If cursor is provided, decode and apply WHERE condition
	if p.Cursor != "" {
		decodedVal, err := response.DecodeCursor[any](p.Cursor)
		if err == nil && decodedVal != nil {
			if isDescending {
				queryBuilder = queryBuilder.Where(squirrel.Lt{cleanCol: *decodedVal})
			} else {
				queryBuilder = queryBuilder.Where(squirrel.Gt{cleanCol: *decodedVal})
			}
		}
	}

	if isDescending {
		queryBuilder = queryBuilder.OrderBy(fmt.Sprintf("%s DESC", cleanCol))
	} else {
		queryBuilder = queryBuilder.OrderBy(fmt.Sprintf("%s ASC", cleanCol))
	}

	dataSQL, dataArgs, err := queryBuilder.ToSql()
	if err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to build cursor query: %w", err)
	}

	rows, err := exec.QueryContext(ctx, dataSQL, dataArgs...)
	if err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to execute cursor query: %w", err)
	}

	items, err := ScanAll[T](rows, meta)
	if err != nil {
		return nil, nil, fmt.Errorf("ztatic/data: failed to scan cursor rows: %w", err)
	}

	hasMore := false
	if len(items) > limit {
		hasMore = true
		items = items[:limit]
	}

	var nextCursor string
	if hasMore && len(items) > 0 {
		lastItem := items[len(items)-1]
		if cursorVal, err := extractColumnValue(lastItem, cleanCol, meta); err == nil {
			nextCursor, _ = response.EncodeCursor(cursorVal)
		}
	}

	cursorMeta := &response.CursorMeta{
		Cursor:     p.Cursor,
		NextCursor: nextCursor,
		Limit:      limit,
		HasMore:    hasMore,
	}

	return items, cursorMeta, nil
}

func extractColumnValue(entity any, colName string, meta *StructMetadata) (any, error) {
	val := reflect.ValueOf(entity)
	for val.Kind() == reflect.Pointer {
		val = val.Elem()
	}

	if fi, ok := meta.FieldByColumn[colName]; ok {
		fieldVal := getFieldValue(val, fi.IndexPath)
		return fieldVal.Interface(), nil
	}

	return nil, fmt.Errorf("column %s not found in metadata", colName)
}
