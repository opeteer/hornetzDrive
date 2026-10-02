package validation

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
	ztaticErrors "ztatic-go-framework/errors"
)

// Engine is the central validation engine for Ztatic applications.
// It wraps go-playground/validator/v10 with context-awareness, Zero-Trust security rules,
// automated JSON tag resolution, and dynamic custom messages.
type Engine struct {
	validator *validator.Validate
	resolver  DatabaseResolver
	mu        sync.RWMutex
}

// New initializes a new validation Engine configured with zero-trust defaults.
func New() *Engine {
	v := validator.New()

	// 1. Register intelligent tag name extractor (JSON -> Form -> Query -> StructField)
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		name := strings.SplitN(fld.Tag.Get("json"), ",", 2)[0]
		if name == "-" {
			return ""
		}
		if name != "" {
			return name
		}
		name = strings.SplitN(fld.Tag.Get("form"), ",", 2)[0]
		if name != "" && name != "-" {
			return name
		}
		name = strings.SplitN(fld.Tag.Get("query"), ",", 2)[0]
		if name != "" && name != "-" {
			return name
		}
		return fld.Name
	})

	eng := &Engine{
		validator: v,
	}

	// 2. Register built-in Zero-Trust security and domain rules
	registerBuiltInRules(v, eng.GetDatabaseResolver)

	return eng
}

// SetDatabaseResolver configures the engine-level database resolver for `unique` and `exists` rules.
func (e *Engine) SetDatabaseResolver(r DatabaseResolver) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.resolver = r
}

// GetDatabaseResolver retrieves the registered database resolver.
func (e *Engine) GetDatabaseResolver() DatabaseResolver {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.resolver
}

// Validator returns the underlying *validator.Validate instance for advanced custom rules.
func (e *Engine) Validator() *validator.Validate {
	return e.validator
}

// Validate executes struct tag validation with a background context.
// Satisfies the echo.Validator interface.
func (e *Engine) Validate(i any) error {
	return e.ValidateCtx(context.Background(), i)
}

// ValidateCtx executes struct tag validation and model self-validation with context.
func (e *Engine) ValidateCtx(ctx context.Context, i any) error {
	if i == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Extract any custom error messages from struct tags (message/msg)
	tagMsgs := ExtractStructTagMessages(i)

	// 2. Run struct validation with context
	if err := e.validator.StructCtx(ctx, i); err != nil {
		var valErrors validator.ValidationErrors
		if errors.As(err, &valErrors) {
			violations := make([]ztaticErrors.FieldViolation, 0, len(valErrors))
			for _, fe := range valErrors {
				msg := ResolveMessage(tagMsgs, fe)
				violations = append(violations, ztaticErrors.FieldViolation{
					Field:   fe.Field(),
					Rule:    fe.Tag(),
					Message: msg,
					Value:   fe.Value(),
				})
			}
			return ztaticErrors.Validation(fmt.Sprintf("Validation failed on %d field(s)", len(violations)), violations...).
				WithInternal(err)
		}
		return ztaticErrors.Map(err)
	}

	// 3. Execute model self-validation if implemented
	if cv, ok := i.(CustomValidator); ok {
		if err := cv.Validate(ctx); err != nil {
			return ztaticErrors.Map(err)
		}
	} else if sv, ok := i.(SelfValidator); ok {
		if err := sv.Validate(); err != nil {
			return ztaticErrors.Map(err)
		}
	}

	return nil
}

// DefaultEngine is the global shared validation engine.
var DefaultEngine = New()

// Validate validates a struct using DefaultEngine.
func Validate(i any) error {
	return DefaultEngine.Validate(i)
}

// ValidateCtx validates a struct with context using DefaultEngine.
func ValidateCtx(ctx context.Context, i any) error {
	return DefaultEngine.ValidateCtx(ctx, i)
}

// SetDatabaseResolver sets the database resolver on DefaultEngine.
func SetDatabaseResolver(r DatabaseResolver) {
	DefaultEngine.SetDatabaseResolver(r)
}
