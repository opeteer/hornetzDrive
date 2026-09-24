package rapid

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

// Resource defines a standard generic RESTful interface for any data model.
type Resource[T any] interface {
	FindAll(c *echo.Context) ([]T, error)
	FindByID(c *echo.Context, id string) (T, error)
	Create(c *echo.Context, item *T) (T, error)
	Update(c *echo.Context, id string, item *T) (T, error)
	Delete(c *echo.Context, id string) error
}

// RegisterResource is a rapid DX scaffolder. It automatically mounts standard
// RESTful endpoints (GET, POST, PUT, DELETE) onto an Echo Group for the given
// generic Resource interface. It automatically integrates Ztatic's `BindAndValidate`.
func RegisterResource[T any](g *echo.Group, path string, res Resource[T]) {
	group := g.Group(path)

	// GET /resource - FindAll
	group.GET("", func(c *echo.Context) error {
		items, err := res.FindAll(c)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, items)
	})

	// GET /resource/:id - FindByID
	group.GET("/:id", func(c *echo.Context) error {
		id := c.Param("id")
		item, err := res.FindByID(c, id)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, item)
	})

	// POST /resource - Create
	group.POST("", func(c *echo.Context) error {
		var item T
		// Ztatic DX: Automatically binds the payload and executes struct validation tags.
		if err := BindAndValidate(c, &item); err != nil {
			return err
		}

		created, err := res.Create(c, &item)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusCreated, created)
	})

	// PUT /resource/:id - Update
	group.PUT("/:id", func(c *echo.Context) error {
		id := c.Param("id")
		var item T

		if err := BindAndValidate(c, &item); err != nil {
			return err
		}

		updated, err := res.Update(c, id, &item)
		if err != nil {
			return err
		}
		return c.JSON(http.StatusOK, updated)
	})

	// DELETE /resource/:id - Delete
	group.DELETE("/:id", func(c *echo.Context) error {
		id := c.Param("id")
		if err := res.Delete(c, id); err != nil {
			return err
		}
		return c.NoContent(http.StatusNoContent)
	})
}
