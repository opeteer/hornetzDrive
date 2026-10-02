package ztatic_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ztatic-go-framework"
	ztaticerrors "ztatic-go-framework/errors"
	"ztatic-go-framework/rapid"
	"ztatic-go-framework/response"
)

type TestArticle struct {
	ID    int    `json:"id"`
	Title string `json:"title"`
}

type mockPaginatedArticleRepo struct {
	articles []TestArticle
}

func (m *mockPaginatedArticleRepo) FindAll(c *ztatic.Context) ([]TestArticle, error) {
	return m.articles, nil
}

func (m *mockPaginatedArticleRepo) FindAllPaginated(c *ztatic.Context, p response.PageParams) ([]TestArticle, int64, error) {
	total := int64(len(m.articles))
	start := p.Offset()
	if start >= len(m.articles) {
		return []TestArticle{}, total, nil
	}
	end := start + p.Limit()
	if end > len(m.articles) {
		end = len(m.articles)
	}
	return m.articles[start:end], total, nil
}

func (m *mockPaginatedArticleRepo) FindByID(c *ztatic.Context, id string) (TestArticle, error) {
	for _, a := range m.articles {
		if fmt.Sprintf("%d", a.ID) == id {
			return a, nil
		}
	}
	return TestArticle{}, ztatic.ErrNotFound("article not found")
}

func (m *mockPaginatedArticleRepo) Create(c *ztatic.Context, item *TestArticle) (TestArticle, error) {
	item.ID = len(m.articles) + 1
	m.articles = append(m.articles, *item)
	return *item, nil
}

func (m *mockPaginatedArticleRepo) Update(c *ztatic.Context, id string, item *TestArticle) (TestArticle, error) {
	return *item, nil
}

func (m *mockPaginatedArticleRepo) Delete(c *ztatic.Context, id string) error {
	return nil
}

// -----------------------------------------------------------------------------
// 1. Success, Created, and NoContent Envelope Tests
// -----------------------------------------------------------------------------

func TestIntegration_ResponseEnvelope_Success_Created_NoContent(t *testing.T) {
	app := ztatic.NewSecure()

	app.GET("/api/users/me", func(c *ztatic.Context) error {
		return ztatic.OK(c, map[string]any{"username": "admin", "role": "superadmin"}, response.WithMeta("role_verified", true))
	})

	app.POST("/api/users", func(c *ztatic.Context) error {
		return ztatic.Created(c, map[string]any{"id": 101, "username": "newuser"}, "/api/users/101")
	})

	app.DELETE("/api/users/:id", func(c *ztatic.Context) error {
		return ztatic.NoContent(c)
	})

	// 1. Test OK (200)
	reqOK := httptest.NewRequest(http.MethodGet, "/api/users/me", nil)
	recOK := httptest.NewRecorder()
	app.ServeHTTP(recOK, reqOK)

	if recOK.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recOK.Code)
	}

	var parsedOK ztatic.Envelope[map[string]any]
	if err := json.Unmarshal(recOK.Body.Bytes(), &parsedOK); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if !parsedOK.Success {
		t.Errorf("expected success true")
	}
	if parsedOK.Data["username"] != "admin" {
		t.Errorf("expected username admin, got %v", parsedOK.Data["username"])
	}
	if parsedOK.Meta == nil || parsedOK.Meta.RequestID == "" {
		t.Errorf("expected request_id in envelope metadata")
	}
	if parsedOK.Meta.Duration == "" {
		t.Errorf("expected duration in envelope metadata")
	}
	if parsedOK.Meta.Extra["role_verified"] != true {
		t.Errorf("expected extra meta role_verified: true")
	}

	// 2. Test Created (201)
	reqCreated := httptest.NewRequest(http.MethodPost, "/api/users", nil)
	recCreated := httptest.NewRecorder()
	app.ServeHTTP(recCreated, reqCreated)

	if recCreated.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created, got %d", recCreated.Code)
	}
	if recCreated.Header().Get("Location") != "/api/users/101" {
		t.Errorf("expected Location header /api/users/101, got %s", recCreated.Header().Get("Location"))
	}

	// 3. Test NoContent (204)
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/users/101", nil)
	recDel := httptest.NewRecorder()
	app.ServeHTTP(recDel, reqDel)

	if recDel.Code != http.StatusNoContent {
		t.Fatalf("expected 204 NoContent, got %d", recDel.Code)
	}
	if recDel.Body.Len() != 0 {
		t.Errorf("expected empty body for 204, got: %s", recDel.Body.String())
	}
}

// -----------------------------------------------------------------------------
// 2. Offset / Page-Based Pagination with HATEOAS Links & Link Header
// -----------------------------------------------------------------------------

func TestIntegration_ResponseEnvelope_Pagination(t *testing.T) {
	app := ztatic.NewSecure()

	// Simulate collection of 45 items
	allArticles := make([]TestArticle, 45)
	for i := range allArticles {
		allArticles[i] = TestArticle{ID: i + 1, Title: fmt.Sprintf("Article #%d", i+1)}
	}

	app.GET("/api/articles", func(c *ztatic.Context) error {
		p := ztatic.ExtractPagination(c)
		total := int64(len(allArticles))

		start := p.Offset()
		end := start + p.Limit()
		if start > len(allArticles) {
			start = len(allArticles)
		}
		if end > len(allArticles) {
			end = len(allArticles)
		}

		slice := allArticles[start:end]
		meta := p.WithTotal(total)
		return ztatic.Paginated(c, slice, meta)
	})

	// Request page 2 with 10 items per page
	req := httptest.NewRequest(http.MethodGet, "/api/articles?page=2&per_page=10&tag=tech", nil)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var parsed ztatic.Envelope[[]TestArticle]
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if !parsed.Success {
		t.Errorf("expected success true")
	}
	if len(parsed.Data) != 10 {
		t.Errorf("expected 10 items on page 2, got %d", len(parsed.Data))
	}
	if parsed.Data[0].ID != 11 {
		t.Errorf("expected first item on page 2 to have ID 11, got %d", parsed.Data[0].ID)
	}

	// Verify Pagination metadata
	pg := parsed.Pagination
	if pg == nil {
		t.Fatalf("expected pagination metadata")
	}
	if pg.Page != 2 || pg.PerPage != 10 || pg.TotalItems != 45 || pg.TotalPages != 5 {
		t.Errorf("unexpected pagination metadata: %+v", pg)
	}
	if !pg.HasNext || !pg.HasPrev {
		t.Errorf("expected both has_next and has_prev on page 2 of 5")
	}

	// Verify HATEOAS Links
	links := parsed.Links
	if links == nil {
		t.Fatalf("expected HATEOAS links")
	}
	if !strings.Contains(links.Self, "page=2") || !strings.Contains(links.Self, "tag=tech") {
		t.Errorf("expected self link to retain query params: %s", links.Self)
	}
	if !strings.Contains(links.Prev, "page=1") {
		t.Errorf("expected prev link page=1: %s", links.Prev)
	}
	if !strings.Contains(links.Next, "page=3") {
		t.Errorf("expected next link page=3: %s", links.Next)
	}
	if !strings.Contains(links.Last, "page=5") {
		t.Errorf("expected last link page=5: %s", links.Last)
	}

	// Verify RFC 5988 Link HTTP Header
	linkHeader := rec.Header().Get("Link")
	if linkHeader == "" {
		t.Errorf("expected Link HTTP header to be present")
	}
	if !strings.Contains(linkHeader, `rel="next"`) || !strings.Contains(linkHeader, `rel="prev"`) {
		t.Errorf("expected Link header to contain rels: %s", linkHeader)
	}
}

// -----------------------------------------------------------------------------
// 3. Cursor-Based Pagination
// -----------------------------------------------------------------------------

func TestIntegration_ResponseEnvelope_CursorPagination(t *testing.T) {
	app := ztatic.NewSecure()

	type FeedCursor struct {
		LastID int `json:"last_id"`
	}

	app.GET("/api/feed", func(c *ztatic.Context) error {
		cp := ztatic.ExtractCursor(c)

		var startID int
		if cp.Cursor != "" {
			decoded, err := response.DecodeCursor[FeedCursor](cp.Cursor)
			if err != nil {
				return ztatic.ErrBadRequest("invalid cursor")
			}
			startID = decoded.LastID
		}

		// Generate items after startID
		var items []TestArticle
		for i := startID + 1; i <= startID+cp.Limit; i++ {
			items = append(items, TestArticle{ID: i, Title: fmt.Sprintf("Feed item #%d", i)})
		}

		lastItem := items[len(items)-1]
		nextTok, _ := response.EncodeCursor(FeedCursor{LastID: lastItem.ID})

		meta := &ztatic.CursorMeta{
			Cursor:     cp.Cursor,
			NextCursor: nextTok,
			Limit:      cp.Limit,
			HasMore:    true,
		}

		return ztatic.CursorPaginated(c, items, meta)
	})

	// Initial request (no cursor)
	req1 := httptest.NewRequest(http.MethodGet, "/api/feed?limit=5", nil)
	rec1 := httptest.NewRecorder()
	app.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec1.Code)
	}

	var parsed1 ztatic.Envelope[[]TestArticle]
	if err := json.Unmarshal(rec1.Body.Bytes(), &parsed1); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(parsed1.Data) != 5 || parsed1.Cursor.NextCursor == "" {
		t.Fatalf("expected 5 items and next_cursor token")
	}

	// Follow-up request using returned next_cursor
	nextCursor := parsed1.Cursor.NextCursor
	req2 := httptest.NewRequest(http.MethodGet, "/api/feed?cursor="+nextCursor+"&limit=5", nil)
	rec2 := httptest.NewRecorder()
	app.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusOK {
		t.Fatalf("expected 200 OK on page 2, got %d", rec2.Code)
	}

	var parsed2 ztatic.Envelope[[]TestArticle]
	if err := json.Unmarshal(rec2.Body.Bytes(), &parsed2); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if parsed2.Data[0].ID != 6 {
		t.Errorf("expected first item of page 2 to have ID 6, got %d", parsed2.Data[0].ID)
	}
}

// -----------------------------------------------------------------------------
// 4. Standardized Error Envelopes with Zero-Trust Sanitization
// -----------------------------------------------------------------------------

func TestIntegration_ResponseEnvelope_Errors(t *testing.T) {
	app := ztatic.NewSecure()

	app.GET("/api/validation-fail", func(c *ztatic.Context) error {
		return ztatic.ErrValidation("submission failed",
			ztaticerrors.FieldViolation{Field: "email", Rule: "email", Message: "must be valid"},
			ztaticerrors.FieldViolation{Field: "age", Rule: "min", Message: "must be >= 18"},
		)
	})

	app.GET("/api/crash", func(c *ztatic.Context) error {
		// Production Zero-Trust test: internal database secret
		secretErr := errors.New("pq: password authentication failed for postgres")
		return ztatic.ErrInternal("database failure").WithInternal(secretErr).WithStack()
	})

	// 1. Validation error (422)
	reqVal := httptest.NewRequest(http.MethodGet, "/api/validation-fail", nil)
	recVal := httptest.NewRecorder()
	app.ServeHTTP(recVal, reqVal)

	if recVal.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity, got %d", recVal.Code)
	}

	var parsedVal map[string]any
	if err := json.Unmarshal(recVal.Body.Bytes(), &parsedVal); err != nil {
		t.Fatalf("failed to unmarshal validation JSON: %v", err)
	}

	if parsedVal["success"] != false {
		t.Errorf("expected success false, got %v", parsedVal["success"])
	}
	errObj, ok := parsedVal["error"].(map[string]any)
	if !ok || errObj["code"] != "VALIDATION_FAILED" {
		t.Errorf("expected VALIDATION_FAILED error code, got %+v", errObj)
	}
	details, ok := errObj["details"].([]any)
	if !ok || len(details) != 2 {
		t.Errorf("expected 2 field violation details, got %+v", details)
	}
	metaObj, ok := parsedVal["meta"].(map[string]any)
	if !ok || metaObj["request_id"] == "" {
		t.Errorf("expected request_id in envelope meta")
	}

	// 2. Production Crash test (500)
	reqCrash := httptest.NewRequest(http.MethodGet, "/api/crash", nil)
	recCrash := httptest.NewRecorder()
	app.ServeHTTP(recCrash, reqCrash)

	if recCrash.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 Internal Server Error, got %d", recCrash.Code)
	}

	var parsedCrash map[string]any
	if err := json.Unmarshal(recCrash.Body.Bytes(), &parsedCrash); err != nil {
		t.Fatalf("failed to unmarshal crash JSON: %v", err)
	}

	if parsedCrash["success"] != false {
		t.Errorf("expected success false")
	}
	crashErr := parsedCrash["error"].(map[string]any)
	// Zero-Trust: internal error and stack must NOT be leaked
	if crashErr["internal"] != nil && crashErr["internal"] != "" {
		t.Errorf("internal database secret leaked in response: %v", crashErr["internal"])
	}
	if crashErr["stack"] != nil && crashErr["stack"] != "" {
		t.Errorf("stack trace leaked in response: %v", crashErr["stack"])
	}
}

// -----------------------------------------------------------------------------
// 5. Rapid PaginatedResource Scaffolding Integration
// -----------------------------------------------------------------------------

func TestIntegration_RapidResource_PaginatedResource(t *testing.T) {
	app := ztatic.NewSecure()

	articles := []TestArticle{
		{ID: 1, Title: "Article One"},
		{ID: 2, Title: "Article Two"},
		{ID: 3, Title: "Article Three"},
	}
	repo := &mockPaginatedArticleRepo{articles: articles}

	// Mount resource under /api/articles
	rapid.RegisterResource(app.Group("/api"), "articles", repo)

	// 1. GET /api/articles with pagination
	reqAll := httptest.NewRequest(http.MethodGet, "/api/articles?page=1&per_page=2", nil)
	recAll := httptest.NewRecorder()
	app.ServeHTTP(recAll, reqAll)

	if recAll.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", recAll.Code, recAll.Body.String())
	}

	var parsedAll ztatic.Envelope[[]TestArticle]
	if err := json.Unmarshal(recAll.Body.Bytes(), &parsedAll); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if !parsedAll.Success {
		t.Errorf("expected success true")
	}
	if len(parsedAll.Data) != 2 {
		t.Errorf("expected 2 items, got %d", len(parsedAll.Data))
	}
	if parsedAll.Pagination == nil || parsedAll.Pagination.TotalItems != 3 {
		t.Errorf("expected total_items 3, got %+v", parsedAll.Pagination)
	}

	// 2. GET /api/articles/2 (FindByID)
	reqByID := httptest.NewRequest(http.MethodGet, "/api/articles/2", nil)
	recByID := httptest.NewRecorder()
	app.ServeHTTP(recByID, reqByID)

	if recByID.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recByID.Code)
	}

	var parsedByID ztatic.Envelope[TestArticle]
	if err := json.Unmarshal(recByID.Body.Bytes(), &parsedByID); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	if !parsedByID.Success || parsedByID.Data.ID != 2 {
		t.Errorf("expected article 2, got %+v", parsedByID)
	}

	// 3. DELETE /api/articles/2
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/articles/2", nil)
	recDel := httptest.NewRecorder()
	app.ServeHTTP(recDel, reqDel)

	if recDel.Code != http.StatusNoContent {
		t.Errorf("expected 204 NoContent, got %d", recDel.Code)
	}
}
