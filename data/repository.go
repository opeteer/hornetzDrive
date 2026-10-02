package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/labstack/echo/v5"
	"ztatic-go-framework/response"
	"ztatic-go-framework/security/crypto"
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
	DB          *DBEngine
	TableName   string
	PrimaryKey  string
	Metadata    *StructMetadata
	CipherSuite *crypto.CipherSuite
	Tx          *sql.Tx
}

// NewBaseRepository instantiates a generic repository for the specified SQL table.
func NewBaseRepository[T any](db *DBEngine, tableName string) *BaseRepository[T] {
	meta := GetMetadata[T]()
	return &BaseRepository[T]{
		DB:          db,
		TableName:   tableName,
		PrimaryKey:  meta.PrimaryKeyCol,
		Metadata:    meta,
		CipherSuite: crypto.GetDefaultCipherSuite(),
	}
}

// WithTx returns a shallow clone of the repository operating within the designated transaction.
func (r *BaseRepository[T]) WithTx(tx *sql.Tx) *BaseRepository[T] {
	clone := *r
	clone.Tx = tx
	return &clone
}

func (r *BaseRepository[T]) getExecutor(ctx context.Context) DBExecutor {
	if r.Tx != nil {
		return r.Tx
	}
	if r.DB != nil {
		return r.DB.GetExecutor(ctx)
	}
	return nil
}

func (r *BaseRepository[T]) primaryKeyCol() string {
	if r.PrimaryKey != "" {
		return r.PrimaryKey
	}
	if r.Metadata != nil && r.Metadata.PrimaryKeyCol != "" {
		return r.Metadata.PrimaryKeyCol
	}
	return "id"
}

// SelectBuilder initializes a squirrel.SelectBuilder for the repository table
// selecting all mapped model columns.
func (r *BaseRepository[T]) SelectBuilder() squirrel.SelectBuilder {
	cols := []string{"*"}
	if r.Metadata != nil && len(r.Metadata.Columns) > 0 {
		cols = r.Metadata.Columns
	}

	builder := r.DB.Builder
	return builder.Select(cols...).From(r.TableName)
}

// EncryptModel encrypts fields tagged with `ztatic:"encrypt"` on the provided model.
func (r *BaseRepository[T]) EncryptModel(entity *T) error {
	cs := r.CipherSuite
	if cs == nil {
		cs = crypto.GetDefaultCipherSuite()
	}
	if cs == nil {
		return errors.New("ztatic/data: cipher suite is uninitialized for model encryption; call app.SetCipherKey(...)")
	}
	return crypto.ProcessStruct(entity, cs, true)
}

// DecryptModel decrypts fields tagged with `ztatic:"encrypt"` on the provided model.
func (r *BaseRepository[T]) DecryptModel(entity *T) error {
	cs := r.CipherSuite
	if cs == nil {
		cs = crypto.GetDefaultCipherSuite()
	}
	if cs == nil {
		return errors.New("ztatic/data: cipher suite is uninitialized for model decryption; call app.SetCipherKey(...)")
	}
	return crypto.ProcessStruct(entity, cs, false)
}

// QueryByID retrieves a single entity by its primary key using a custom scan function.
// Maintained for backward compatibility.
func (r *BaseRepository[T]) QueryByID(ctx context.Context, id any, scanFn func(row Scanner, entity *T) error) (*T, error) {
	query, args, err := r.DB.Builder.
		Select("*").
		From(r.TableName).
		Where(squirrel.Eq{r.primaryKeyCol(): id}).
		ToSql()

	if err != nil {
		return nil, err
	}

	exec := r.getExecutor(ctx)
	if exec == nil {
		return nil, errors.New("ztatic/data: database executor is uninitialized")
	}

	row := exec.QueryRowContext(ctx, query, args...)

	var entity T
	if err := scanFn(row, &entity); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}

	_ = r.DecryptModel(&entity)
	return &entity, nil
}

// GetByID retrieves a single entity by its primary key with automatic struct mapping and decryption.
func (r *BaseRepository[T]) GetByID(ctx context.Context, id any) (*T, error) {
	exec := r.getExecutor(ctx)
	if exec == nil {
		return nil, errors.New("ztatic/data: database executor is uninitialized")
	}

	query, args, err := r.SelectBuilder().
		Where(squirrel.Eq{r.primaryKeyCol(): id}).
		Limit(1).
		ToSql()

	if err != nil {
		return nil, err
	}

	rows, err := exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, ErrNotFound
	}

	entity, err := ScanOne[T](rows, r.Metadata)
	if err != nil {
		return nil, err
	}

	return entity, nil
}

// Find retrieves all entities matching the provided query options.
func (r *BaseRepository[T]) Find(ctx context.Context, opts ...QueryOption) ([]T, error) {
	exec := r.getExecutor(ctx)
	if exec == nil {
		return nil, errors.New("ztatic/data: database executor is uninitialized")
	}

	builder := ApplyOptions(r.SelectBuilder(), opts)
	query, args, err := builder.ToSql()
	if err != nil {
		return nil, err
	}

	rows, err := exec.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}

	return ScanAll[T](rows, r.Metadata)
}

// Query is an alias for Find.
func (r *BaseRepository[T]) Query(ctx context.Context, opts ...QueryOption) ([]T, error) {
	return r.Find(ctx, opts...)
}

// FindOne retrieves the first entity matching the provided query options.
func (r *BaseRepository[T]) FindOne(ctx context.Context, opts ...QueryOption) (*T, error) {
	opts = append(opts, Limit(1))
	items, err := r.Find(ctx, opts...)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	return &items[0], nil
}

// FindPaginated executes an offset-paginated query, calculating totals and returning metadata.
func (r *BaseRepository[T]) FindPaginated(ctx context.Context, p response.PageParams, opts ...QueryOption) ([]T, *response.PaginationMeta, error) {
	exec := r.getExecutor(ctx)
	if exec == nil {
		return nil, nil, errors.New("ztatic/data: database executor is uninitialized")
	}

	builder := ApplyOptions(r.SelectBuilder(), opts)
	return PaginateSelect[T](ctx, exec, builder, p, r.Metadata)
}

// FindCursor executes a keyset/cursor-paginated query.
func (r *BaseRepository[T]) FindCursor(ctx context.Context, p response.CursorParams, cursorCol string, opts ...QueryOption) ([]T, *response.CursorMeta, error) {
	exec := r.getExecutor(ctx)
	if exec == nil {
		return nil, nil, errors.New("ztatic/data: database executor is uninitialized")
	}

	builder := ApplyOptions(r.SelectBuilder(), opts)
	return PaginateCursorSelect[T](ctx, exec, builder, p, cursorCol, r.Metadata)
}

// Insert persists a new entity record into the database table.
// If the primary key is auto-incrementing, its generated value is populated back onto entity.
func (r *BaseRepository[T]) Insert(ctx context.Context, entity *T) error {
	if entity == nil {
		return errors.New("ztatic/data: entity is nil")
	}

	exec := r.getExecutor(ctx)
	if exec == nil {
		return errors.New("ztatic/data: database executor is uninitialized")
	}

	populateDefaultTimestamps(entity)

	cols, vals, err := ExtractValues(entity, r.Metadata, true)
	if err != nil {
		return err
	}

	query, args, err := r.DB.Builder.
		Insert(r.TableName).
		Columns(cols...).
		Values(vals...).
		ToSql()

	if err != nil {
		return err
	}

	res, err := exec.ExecContext(ctx, query, args...)
	if err != nil {
		return err
	}

	// Auto-increment primary key population
	if r.Metadata != nil && r.Metadata.PrimaryKeyField != nil && r.Metadata.PrimaryKeyField.IsAutoIncrement {
		if id, err := res.LastInsertId(); err == nil && id > 0 {
			_ = SetPrimaryKeyValue(entity, r.Metadata, id)
		}
	}

	return nil
}

// InsertMany persists multiple entities within a single multi-row INSERT statement.
func (r *BaseRepository[T]) InsertMany(ctx context.Context, entities []*T) error {
	if len(entities) == 0 {
		return nil
	}

	exec := r.getExecutor(ctx)
	if exec == nil {
		return errors.New("ztatic/data: database executor is uninitialized")
	}

	for _, entity := range entities {
		populateDefaultTimestamps(entity)
	}

	firstCols, _, err := ExtractValues(entities[0], r.Metadata, true)
	if err != nil {
		return err
	}

	insertBuilder := r.DB.Builder.Insert(r.TableName).Columns(firstCols...)
	for _, entity := range entities {
		_, vals, err := ExtractValues(entity, r.Metadata, true)
		if err != nil {
			return err
		}
		insertBuilder = insertBuilder.Values(vals...)
	}

	query, args, err := insertBuilder.ToSql()
	if err != nil {
		return err
	}

	_, err = exec.ExecContext(ctx, query, args...)
	return err
}

// Save updates an existing record identified by its primary key.
func (r *BaseRepository[T]) Save(ctx context.Context, entity *T) error {
	if entity == nil {
		return errors.New("ztatic/data: entity is nil")
	}

	exec := r.getExecutor(ctx)
	if exec == nil {
		return errors.New("ztatic/data: database executor is uninitialized")
	}

	pkVal, err := GetPrimaryKeyValue(entity, r.Metadata)
	if err != nil {
		return fmt.Errorf("ztatic/data: failed to get primary key for update: %w", err)
	}

	cols, vals, err := ExtractValues(entity, r.Metadata, false)
	if err != nil {
		return err
	}

	updateBuilder := r.DB.Builder.Update(r.TableName)
	for i, col := range cols {
		updateBuilder = updateBuilder.Set(col, vals[i])
	}
	updateBuilder = updateBuilder.Where(squirrel.Eq{r.primaryKeyCol(): pkVal})

	query, args, err := updateBuilder.ToSql()
	if err != nil {
		return err
	}

	result, err := exec.ExecContext(ctx, query, args...)
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

// UpdateEntity is an alias for Save.
func (r *BaseRepository[T]) UpdateEntity(ctx context.Context, entity *T) error {
	return r.Save(ctx, entity)
}

// UpdateColumns updates specific column values for a record by its primary key.
func (r *BaseRepository[T]) UpdateColumns(ctx context.Context, id any, values map[string]any) error {
	if len(values) == 0 {
		return nil
	}

	exec := r.getExecutor(ctx)
	if exec == nil {
		return errors.New("ztatic/data: database executor is uninitialized")
	}

	updateBuilder := r.DB.Builder.Update(r.TableName)
	for col, val := range values {
		clean := cleanIdentifier(col)
		if clean != "" {
			updateBuilder = updateBuilder.Set(clean, val)
		}
	}
	updateBuilder = updateBuilder.Where(squirrel.Eq{r.primaryKeyCol(): id})

	query, args, err := updateBuilder.ToSql()
	if err != nil {
		return err
	}

	result, err := exec.ExecContext(ctx, query, args...)
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

// DeleteByID removes a record by its primary key.
func (r *BaseRepository[T]) DeleteByID(ctx context.Context, id any) error {
	exec := r.getExecutor(ctx)
	if exec == nil {
		return errors.New("ztatic/data: database executor is uninitialized")
	}

	query, args, err := r.DB.Builder.
		Delete(r.TableName).
		Where(squirrel.Eq{r.primaryKeyCol(): id}).
		ToSql()

	if err != nil {
		return err
	}

	result, err := exec.ExecContext(ctx, query, args...)
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

// DeleteWhere removes all records matching the predicate.
func (r *BaseRepository[T]) DeleteWhere(ctx context.Context, pred any, args ...any) (int64, error) {
	exec := r.getExecutor(ctx)
	if exec == nil {
		return 0, errors.New("ztatic/data: database executor is uninitialized")
	}

	query, queryArgs, err := r.DB.Builder.
		Delete(r.TableName).
		Where(pred, args...).
		ToSql()

	if err != nil {
		return 0, err
	}

	result, err := exec.ExecContext(ctx, query, queryArgs...)
	if err != nil {
		return 0, err
	}

	return result.RowsAffected()
}

// Count returns the total number of records matching the query options.
func (r *BaseRepository[T]) Count(ctx context.Context, opts ...QueryOption) (int64, error) {
	exec := r.getExecutor(ctx)
	if exec == nil {
		return 0, errors.New("ztatic/data: database executor is uninitialized")
	}

	builder := ApplyOptions(r.DB.Builder.Select("COUNT(*)").From(r.TableName), opts)
	query, args, err := builder.ToSql()
	if err != nil {
		return 0, err
	}

	var count int64
	row := exec.QueryRowContext(ctx, query, args...)
	if err := row.Scan(&count); err != nil {
		return 0, err
	}

	return count, nil
}

// Exists returns true if at least one record matches the query options.
func (r *BaseRepository[T]) Exists(ctx context.Context, opts ...QueryOption) (bool, error) {
	count, err := r.Count(ctx, opts...)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// --- rapid.Resource[T] & rapid.PaginatedResource[T] Implementations ---

// FindAll implements rapid.Resource[T].
func (r *BaseRepository[T]) FindAll(c *echo.Context) ([]T, error) {
	items, err := r.Find(c.Request().Context())
	if err != nil {
		return nil, err
	}
	return items, nil
}

// FindByID implements rapid.Resource[T].
func (r *BaseRepository[T]) FindByID(c *echo.Context, id string) (T, error) {
	item, err := r.GetByID(c.Request().Context(), id)
	if err != nil {
		var empty T
		if errors.Is(err, ErrNotFound) {
			return empty, echo.NewHTTPError(http.StatusNotFound, "ztatic/data: record not found")
		}
		return empty, err
	}
	return *item, nil
}

// Create implements rapid.Resource[T].
func (r *BaseRepository[T]) Create(c *echo.Context, item *T) (T, error) {
	var empty T
	if item == nil {
		return empty, echo.NewHTTPError(http.StatusBadRequest, "ztatic/data: payload cannot be nil")
	}
	if err := r.Insert(c.Request().Context(), item); err != nil {
		return empty, err
	}
	return *item, nil
}

// Update implements rapid.Resource[T].
func (r *BaseRepository[T]) Update(c *echo.Context, id string, item *T) (T, error) {
	var empty T
	if item == nil {
		return empty, echo.NewHTTPError(http.StatusBadRequest, "ztatic/data: payload cannot be nil")
	}
	if err := SetPrimaryKeyValue(item, r.Metadata, id); err != nil {
		// If string to int conversion fails, keep going as primary key might already be populated
		_ = err
	}
	if err := r.Save(c.Request().Context(), item); err != nil {
		if errors.Is(err, ErrNotFound) {
			return empty, echo.NewHTTPError(http.StatusNotFound, "ztatic/data: record not found")
		}
		return empty, err
	}
	return *item, nil
}

// Delete implements rapid.Resource[T].
func (r *BaseRepository[T]) Delete(c *echo.Context, id string) error {
	err := r.DeleteByID(c.Request().Context(), id)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "ztatic/data: record not found")
		}
		return err
	}
	return nil
}

// FindAllPaginated implements rapid.PaginatedResource[T].
func (r *BaseRepository[T]) FindAllPaginated(c *echo.Context, p response.PageParams) ([]T, int64, error) {
	items, meta, err := r.FindPaginated(c.Request().Context(), p)
	if err != nil {
		return nil, 0, err
	}
	return items, meta.TotalItems, nil
}

func populateDefaultTimestamps(entity any) {
	if entity == nil {
		return
	}
	val := reflect.ValueOf(entity)
	if val.Kind() == reflect.Pointer && !val.IsNil() {
		elem := val.Elem()
		if elem.Kind() == reflect.Struct {
			createdField := elem.FieldByName("CreatedAt")
			if createdField.IsValid() && createdField.CanSet() && createdField.Type() == reflect.TypeOf(time.Time{}) {
				if t, ok := createdField.Interface().(time.Time); ok && t.IsZero() {
					createdField.Set(reflect.ValueOf(time.Now()))
				}
			}
		}
	}
}

