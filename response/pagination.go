package response

import (
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"

	"github.com/Masterminds/squirrel"
	"github.com/labstack/echo/v5"
)

// PaginationMeta contains the mathematical metadata for an offset/page paginated collection.
type PaginationMeta struct {
	Page       int   `json:"page"`
	PerPage    int   `json:"per_page"`
	TotalItems int64 `json:"total_items"`
	TotalPages int   `json:"total_pages"`
	HasNext    bool  `json:"has_next"`
	HasPrev    bool  `json:"has_prev"`
}

// Links models RFC 5988 / JSON:API navigation links.
type Links struct {
	Self  string `json:"self,omitempty"`
	First string `json:"first,omitempty"`
	Prev  string `json:"prev,omitempty"`
	Next  string `json:"next,omitempty"`
	Last  string `json:"last,omitempty"`
}

// PageParams captures validated pagination and ordering parameters from an incoming request.
type PageParams struct {
	Page    int
	PerPage int
	Sort    string
	Order   string
}

// Offset returns the zero-indexed SQL offset.
func (p PageParams) Offset() int {
	if p.Page <= 1 {
		return 0
	}
	return (p.Page - 1) * p.PerPage
}

// Limit returns the SQL limit (per-page count).
func (p PageParams) Limit() int {
	if p.PerPage <= 0 {
		return 20
	}
	return p.PerPage
}

// Apply attaches Limit, Offset, and OrderBy clauses directly to a squirrel.SelectBuilder.
func (p PageParams) Apply(b squirrel.SelectBuilder) squirrel.SelectBuilder {
	b = b.Limit(uint64(p.Limit())).Offset(uint64(p.Offset()))
	if p.Sort != "" {
		// Clean sort field: allow only alphanumeric and underscores to prevent SQL injection
		cleanSort := cleanIdentifier(p.Sort)
		if cleanSort != "" {
			order := strings.ToUpper(strings.TrimSpace(p.Order))
			if order != "DESC" {
				order = "ASC"
			}
			b = b.OrderBy(fmt.Sprintf("%s %s", cleanSort, order))
		}
	}
	return b
}

// WithTotal calculates total pages and navigation flags from a total count.
func (p PageParams) WithTotal(total int64) *PaginationMeta {
	limit := p.Limit()
	totalPages := 0
	if limit > 0 && total > 0 {
		totalPages = int(math.Ceil(float64(total) / float64(limit)))
	}

	page := p.Page
	if page < 1 {
		page = 1
	}

	return &PaginationMeta{
		Page:       page,
		PerPage:    limit,
		TotalItems: total,
		TotalPages: totalPages,
		HasNext:    page < totalPages,
		HasPrev:    page > 1 && (totalPages == 0 || page <= totalPages+1),
	}
}

// PaginationOption defines functional configuration for ExtractPagination.
type PaginationOption func(*paginationOptions)

type paginationOptions struct {
	defaultPageSize int
	maxPageSize     int
}

// WithDefaultPageSize sets a custom fallback page size.
func WithDefaultPageSize(size int) PaginationOption {
	return func(o *paginationOptions) {
		if size > 0 {
			o.defaultPageSize = size
		}
	}
}

// WithMaxPageSize sets the upper limit on allowed items per page to prevent DoS.
func WithMaxPageSize(max int) PaginationOption {
	return func(o *paginationOptions) {
		if max > 0 {
			o.maxPageSize = max
		}
	}
}

// ExtractPagination inspects query parameters and extracts validated pagination options.
// Supported aliases: page/p, per_page/limit/page_size/size, sort/sort_by/order_by, order/dir/direction.
func ExtractPagination(c *echo.Context, opts ...PaginationOption) PageParams {
	cfg := paginationOptions{
		defaultPageSize: 20,
		maxPageSize:     100,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	// 1. Extract Page
	page := 1
	rawPage := c.QueryParam("page")
	if rawPage == "" {
		rawPage = c.QueryParam("p")
	}
	if rawPage != "" {
		if val, err := strconv.Atoi(rawPage); err == nil && val > 0 {
			page = val
		}
	}

	// 2. Extract PerPage / Limit
	perPage := cfg.defaultPageSize
	rawPerPage := c.QueryParam("per_page")
	if rawPerPage == "" {
		rawPerPage = c.QueryParam("limit")
	}
	if rawPerPage == "" {
		rawPerPage = c.QueryParam("page_size")
	}
	if rawPerPage == "" {
		rawPerPage = c.QueryParam("size")
	}
	if rawPerPage != "" {
		if val, err := strconv.Atoi(rawPerPage); err == nil && val > 0 {
			perPage = val
		}
	}
	if perPage > cfg.maxPageSize {
		perPage = cfg.maxPageSize
	}

	// 3. Extract Sort Field
	sort := c.QueryParam("sort")
	if sort == "" {
		sort = c.QueryParam("sort_by")
	}
	if sort == "" {
		sort = c.QueryParam("order_by")
	}

	// 4. Extract Order Direction
	order := strings.ToLower(strings.TrimSpace(c.QueryParam("order")))
	if order == "" {
		order = strings.ToLower(strings.TrimSpace(c.QueryParam("dir")))
	}
	if order == "" {
		order = strings.ToLower(strings.TrimSpace(c.QueryParam("direction")))
	}
	if order != "desc" {
		order = "asc"
	}

	return PageParams{
		Page:    page,
		PerPage: perPage,
		Sort:    sort,
		Order:   order,
	}
}

// GenerateLinks dynamically constructs HATEOAS navigation links preserving any existing query parameters.
func GenerateLinks(c *echo.Context, page, perPage, totalPages int) *Links {
	if c == nil || c.Request() == nil || c.Request().URL == nil {
		return nil
	}

	reqURL := c.Request().URL
	basePath := reqURL.Path

	buildURL := func(targetPage int) string {
		q, _ := url.ParseQuery(reqURL.RawQuery)
		q.Set("page", strconv.Itoa(targetPage))
		q.Set("per_page", strconv.Itoa(perPage))
		return basePath + "?" + q.Encode()
	}

	links := &Links{
		Self:  buildURL(page),
		First: buildURL(1),
	}

	if totalPages > 0 {
		links.Last = buildURL(totalPages)
	}

	if page > 1 {
		links.Prev = buildURL(page - 1)
	}

	if totalPages > 0 && page < totalPages {
		links.Next = buildURL(page + 1)
	}

	return links
}

// SetLinkHeader formats and sets the standard RFC 5988 / RFC 8288 "Link" HTTP header.
func SetLinkHeader(c *echo.Context, links *Links) {
	if c == nil || links == nil {
		return
	}

	var parts []string
	if links.First != "" {
		parts = append(parts, fmt.Sprintf("<%s>; rel=\"first\"", links.First))
	}
	if links.Prev != "" {
		parts = append(parts, fmt.Sprintf("<%s>; rel=\"prev\"", links.Prev))
	}
	if links.Next != "" {
		parts = append(parts, fmt.Sprintf("<%s>; rel=\"next\"", links.Next))
	}
	if links.Last != "" {
		parts = append(parts, fmt.Sprintf("<%s>; rel=\"last\"", links.Last))
	}

	if len(parts) > 0 {
		c.Response().Header().Set("Link", strings.Join(parts, ", "))
	}
}

// cleanIdentifier allows only safe SQL identifiers (letters, digits, underscores, dots) to prevent SQLi in OrderBy.
func cleanIdentifier(s string) string {
	s = strings.TrimSpace(s)
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.') {
			return ""
		}
	}
	return s
}
