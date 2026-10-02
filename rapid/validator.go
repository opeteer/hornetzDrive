package rapid

import (
	"context"
	"fmt"

	"github.com/labstack/echo/v5"
	"ztatic-go-framework/errors"
	"ztatic-go-framework/validation"
)

// StructValidator implements both echo.Validator and validation.ContextValidator interfaces,
// wrapping the Ztatic validation.Engine for robust struct tag validation and sanitization.
type StructValidator struct {
	engine *validation.Engine
}

// NewStructValidator initializes a new validator backed by validation.Engine.
func NewStructValidator() *StructValidator {
	return &StructValidator{engine: validation.New()}
}

// Engine returns the underlying validation.Engine.
func (cv *StructValidator) Engine() *validation.Engine {
	return cv.engine
}

// Validate executes the validation tags on the given struct.
func (cv *StructValidator) Validate(i any) error {
	return cv.engine.Validate(i)
}

// ValidateCtx executes the validation tags on the given struct with context.
func (cv *StructValidator) ValidateCtx(ctx context.Context, i any) error {
	return cv.engine.ValidateCtx(ctx, i)
}

// BindAndValidate is a DX (Developer Experience) helper that performs:
// 1. Request payload binding (JSON/XML/Form/Query)
// 2. Pre-validation input sanitization (sanitize struct tags and Sanitizable hooks)
// 3. Context-aware struct tag validation with custom messages
// in a single atomic call.
func BindAndValidate(c *echo.Context, i any) error {
	// 1. Bind payload to struct
	if err := c.Bind(i); err != nil {
		return errors.BadRequest(fmt.Sprintf("Binding error: %v", err)).WithInternal(err)
	}

	ctx := c.Request().Context()

	// 2. Pre-validation sanitization
	if err := validation.SanitizeCtx(ctx, i); err != nil {
		return errors.BadRequest(fmt.Sprintf("Sanitization error: %v", err)).WithInternal(err)
	}

	// 3. Validate struct tags using the Engine's registered Validator (with context if supported)
	if cv, ok := c.Echo().Validator.(validation.ContextValidator); ok {
		if err := cv.ValidateCtx(ctx, i); err != nil {
			return err
		}
	} else if err := c.Validate(i); err != nil {
		return err
	}

	return nil
}
