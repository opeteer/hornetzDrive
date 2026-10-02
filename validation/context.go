package validation

import (
	"context"
)

type contextKey string

const (
	databaseResolverKey contextKey = "ztatic.validation.database_resolver"
)

// DatabaseResolver abstracts database existence and uniqueness checks.
type DatabaseResolver interface {
	// Exists checks if a record matching the given column and value exists in the table.
	Exists(ctx context.Context, table, column string, value any) (bool, error)
}

// ContextValidator defines the interface for validators that support Go's context.Context.
type ContextValidator interface {
	ValidateCtx(ctx context.Context, i any) error
}

// CustomValidator is an interface that models/DTOs can implement to perform
// custom context-aware domain validation after struct tags have passed.
type CustomValidator interface {
	Validate(ctx context.Context) error
}

// SelfValidator is a simple context-free validation hook for models.
type SelfValidator interface {
	Validate() error
}

// WithDatabaseResolver attaches a DatabaseResolver to the context.
func WithDatabaseResolver(ctx context.Context, resolver DatabaseResolver) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, databaseResolverKey, resolver)
}

// ResolverFromContext retrieves the DatabaseResolver from context, if available.
func ResolverFromContext(ctx context.Context) DatabaseResolver {
	if ctx == nil {
		return nil
	}
	if val, ok := ctx.Value(databaseResolverKey).(DatabaseResolver); ok {
		return val
	}
	return nil
}
