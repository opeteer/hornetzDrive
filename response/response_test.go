package response

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/labstack/echo/v5"
	ztaticerrors "ztatic-go-framework/errors"
)

type sampleUser struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

type sampleCursor struct {
	LastID    int    `json:"last_id"`
	CreatedAt string `json:"created_at"`
}

func TestEnvelope_Success(t *testing.T) {
	u := sampleUser{ID: 1, Name: "Alice"}
	env := NewEnvelope(u)
	env.Meta.RequestID = "req-123"

	bytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if parsed["success"] != true {
		t.Errorf("expected success true, got %v", parsed["success"])
	}
	if parsed["error"] != nil {
		t.Errorf("expected error to be omitted, got %v", parsed["error"])
	}

	dataMap, ok := parsed["data"].(map[string]any)
	if !ok || dataMap["name"] != "Alice" {
		t.Errorf("expected data.name to be Alice, got %v", parsed["data"])
	}

	metaMap, ok := parsed["meta"].(map[string]any)
	if !ok || metaMap["request_id"] != "req-123" {
		t.Errorf("expected meta.request_id to be req-123, got %v", parsed["meta"])
	}
}

func TestEnvelope_EmptySliceSerialization(t *testing.T) {
	var emptyUsers []sampleUser
	env := NewEnvelope(emptyUsers)

	bytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	raw := string(bytes)
	if !strings.Contains(raw, `"data":[]`) {
		t.Errorf("expected empty slice to serialize as [] rather than null, got: %s", raw)
	}
}

func TestEnvelope_ErrorEnvelope(t *testing.T) {
	appErr := ztaticerrors.NotFound("resource missing").WithRequestID("req-err-404")
	env := NewErrorEnvelope(&ztaticerrors.ErrorBody{
		Code:      appErr.Code,
		Message:   appErr.Message,
		Status:    appErr.StatusCode(),
		RequestID: appErr.RequestID,
	}, appErr.RequestID)

	bytes, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("failed to marshal error envelope: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(bytes, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if parsed["success"] != false {
		t.Errorf("expected success false, got %v", parsed["success"])
	}
	if parsed["data"] != nil {
		t.Errorf("expected data to be omitted from error envelope, got %v", parsed["data"])
	}

	errMap, ok := parsed["error"].(map[string]any)
	if !ok || errMap["code"] != "NOT_FOUND" {
		t.Errorf("expected error.code NOT_FOUND, got %v", parsed["error"])
	}
}

func TestPagination_ExtractionAndClamping(t *testing.T) {
	e := echo.New()

	// 1. Valid inputs
	req := httptest.NewRequest(http.MethodGet, "/api/items?page=3&per_page=50&sort=created_at&order=desc", nil)
	c := e.NewContext(req, httptest.NewRecorder())
	p := ExtractPagination(c)

	if p.Page != 3 {
		t.Errorf("expected page 3, got %d", p.Page)
	}
	if p.PerPage != 50 {
		t.Errorf("expected per_page 50, got %d", p.PerPage)
	}
	if p.Sort != "created_at" {
		t.Errorf("expected sort created_at, got %s", p.Sort)
	}
	if p.Order != "desc" {
		t.Errorf("expected order desc, got %s", p.Order)
	}
	if p.Offset() != 100 {
		t.Errorf("expected offset 100, got %d", p.Offset())
	}
	if p.Limit() != 50 {
		t.Errorf("expected limit 50, got %d", p.Limit())
	}

	// 2. Negative page and exceeding max per_page
	req2 := httptest.NewRequest(http.MethodGet, "/api/items?page=-5&per_page=99999", nil)
	c2 := e.NewContext(req2, httptest.NewRecorder())
	p2 := ExtractPagination(c2, WithMaxPageSize(100))

	if p2.Page != 1 {
		t.Errorf("expected clamped page 1, got %d", p2.Page)
	}
	if p2.PerPage != 100 {
		t.Errorf("expected clamped per_page 100, got %d", p2.PerPage)
	}
	if p2.Offset() != 0 {
		t.Errorf("expected offset 0, got %d", p2.Offset())
	}
}

func TestPagination_SquirrelApply(t *testing.T) {
	p := PageParams{
		Page:    2,
		PerPage: 25,
		Sort:    "username",
		Order:   "asc",
	}

	builder := squirrel.Select("id", "username").From("users")
	builder = p.Apply(builder)

	sql, args, err := builder.ToSql()
	if err != nil {
		t.Fatalf("failed to build SQL: %v", err)
	}

	if !strings.Contains(sql, "LIMIT 25 OFFSET 25") {
		t.Errorf("expected LIMIT 25 OFFSET 25 in SQL, got: %s", sql)
	}
	if !strings.Contains(sql, "ORDER BY username ASC") {
		t.Errorf("expected ORDER BY username ASC in SQL, got: %s", sql)
	}
	_ = args
}

func TestPagination_Calculations(t *testing.T) {
	p := PageParams{Page: 2, PerPage: 20}
	meta := p.WithTotal(55)

	if meta.TotalItems != 55 {
		t.Errorf("expected total_items 55, got %d", meta.TotalItems)
	}
	if meta.TotalPages != 3 {
		t.Errorf("expected total_pages 3, got %d", meta.TotalPages)
	}
	if !meta.HasNext {
		t.Errorf("expected has_next true on page 2 of 3")
	}
	if !meta.HasPrev {
		t.Errorf("expected has_prev true on page 2 of 3")
	}

	// Edge case: page 1 of 1
	pFirst := PageParams{Page: 1, PerPage: 20}
	metaFirst := pFirst.WithTotal(15)
	if metaFirst.HasNext || metaFirst.HasPrev {
		t.Errorf("expected has_next false and has_prev false for single page")
	}
}

func TestPagination_HATEOASLinksAndRFC5988Header(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/products?category=electronics&page=2&per_page=10", nil)
	rec := httptest.NewRecorder()
	c := e.NewContext(req, rec)

	links := GenerateLinks(c, 2, 10, 5)
	if links == nil {
		t.Fatalf("expected non-nil links")
	}

	if !strings.Contains(links.Self, "page=2") || !strings.Contains(links.Self, "category=electronics") {
		t.Errorf("expected self link with page=2 and category=electronics, got: %s", links.Self)
	}
	if !strings.Contains(links.First, "page=1") {
		t.Errorf("expected first link page=1, got: %s", links.First)
	}
	if !strings.Contains(links.Prev, "page=1") {
		t.Errorf("expected prev link page=1, got: %s", links.Prev)
	}
	if !strings.Contains(links.Next, "page=3") {
		t.Errorf("expected next link page=3, got: %s", links.Next)
	}
	if !strings.Contains(links.Last, "page=5") {
		t.Errorf("expected last link page=5, got: %s", links.Last)
	}

	SetLinkHeader(c, links)
	linkHeader := rec.Header().Get("Link")
	if linkHeader == "" {
		t.Fatalf("expected Link header to be set")
	}
	if !strings.Contains(linkHeader, `rel="first"`) || !strings.Contains(linkHeader, `rel="next"`) {
		t.Errorf("expected RFC 5988 rels in Link header, got: %s", linkHeader)
	}
}

func TestCursor_EncodeDecode(t *testing.T) {
	original := sampleCursor{LastID: 42, CreatedAt: "2026-09-27T10:00:00Z"}

	token, err := EncodeCursor(original)
	if err != nil {
		t.Fatalf("failed to encode cursor: %v", err)
	}
	if token == "" {
		t.Fatalf("expected non-empty cursor token")
	}

	decoded, err := DecodeCursor[sampleCursor](token)
	if err != nil {
		t.Fatalf("failed to decode cursor: %v", err)
	}
	if decoded == nil || decoded.LastID != 42 || decoded.CreatedAt != original.CreatedAt {
		t.Errorf("decoded cursor does not match original: %+v", decoded)
	}

	// Invalid token test
	_, errInvalid := DecodeCursor[sampleCursor]("not-a-valid-base64!!!")
	if errInvalid == nil {
		t.Errorf("expected error decoding invalid token")
	}
}

func TestCursor_Extraction(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodGet, "/api/stream?cursor=eyJpZCI6MTB9&limit=15&direction=prev", nil)
	c := e.NewContext(req, httptest.NewRecorder())

	cp := ExtractCursor(c)
	if cp.Cursor != "eyJpZCI6MTB9" {
		t.Errorf("expected cursor token, got %s", cp.Cursor)
	}
	if cp.Limit != 15 {
		t.Errorf("expected limit 15, got %d", cp.Limit)
	}
	if cp.Direction != "prev" {
		t.Errorf("expected direction prev, got %s", cp.Direction)
	}
}

func TestHelpers_OK_Created_NoContent_Raw(t *testing.T) {
	e := echo.New()

	// 1. Test OK
	recOK := httptest.NewRecorder()
	cOK := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/test", nil), recOK)
	cOK.Response().Header().Set(echo.HeaderXRequestID, "req-ok-1")

	err := OK(cOK, sampleUser{ID: 10, Name: "Bob"}, WithMeta("source", "cache"))
	if err != nil {
		t.Fatalf("OK returned error: %v", err)
	}
	if recOK.Code != http.StatusOK {
		t.Errorf("expected 200 OK, got %d", recOK.Code)
	}

	var parsedOK Envelope[sampleUser]
	if err := json.Unmarshal(recOK.Body.Bytes(), &parsedOK); err != nil {
		t.Fatalf("failed to unmarshal OK envelope: %v", err)
	}
	if !parsedOK.Success || parsedOK.Data.Name != "Bob" {
		t.Errorf("unexpected parsed envelope: %+v", parsedOK)
	}
	if parsedOK.Meta.Extra["source"] != "cache" {
		t.Errorf("expected custom meta source=cache, got %+v", parsedOK.Meta)
	}

	// 2. Test Created with Location
	recCreated := httptest.NewRecorder()
	cCreated := e.NewContext(httptest.NewRequest(http.MethodPost, "/api/users", nil), recCreated)

	errCreated := Created(cCreated, sampleUser{ID: 11, Name: "Charlie"}, "/api/users/11")
	if errCreated != nil {
		t.Fatalf("Created returned error: %v", errCreated)
	}
	if recCreated.Code != http.StatusCreated {
		t.Errorf("expected 201 Created, got %d", recCreated.Code)
	}
	if recCreated.Header().Get("Location") != "/api/users/11" {
		t.Errorf("expected Location /api/users/11, got %s", recCreated.Header().Get("Location"))
	}

	// 3. Test NoContent
	recNoContent := httptest.NewRecorder()
	cNoContent := e.NewContext(httptest.NewRequest(http.MethodDelete, "/api/users/11", nil), recNoContent)

	errNoContent := NoContent(cNoContent)
	if errNoContent != nil {
		t.Fatalf("NoContent returned error: %v", errNoContent)
	}
	if recNoContent.Code != http.StatusNoContent {
		t.Errorf("expected 204 NoContent, got %d", recNoContent.Code)
	}
	if recNoContent.Body.Len() != 0 {
		t.Errorf("expected empty body for 204, got: %s", recNoContent.Body.String())
	}

	// 4. Test Raw JSON bypass
	recRaw := httptest.NewRecorder()
	cRaw := e.NewContext(httptest.NewRequest(http.MethodGet, "/webhook", nil), recRaw)

	errRaw := Raw(cRaw, http.StatusOK, map[string]string{"event": "ping"})
	if errRaw != nil {
		t.Fatalf("Raw returned error: %v", errRaw)
	}
	if !strings.Contains(recRaw.Body.String(), `{"event":"ping"}`) {
		t.Errorf("expected raw json without envelope, got: %s", recRaw.Body.String())
	}
}

func TestHelpers_PaginatedAndCursorPaginated(t *testing.T) {
	e := echo.New()

	// 1. Paginated Helper
	recPage := httptest.NewRecorder()
	cPage := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/items?page=1&per_page=2", nil), recPage)
	items := []sampleUser{{ID: 1, Name: "U1"}, {ID: 2, Name: "U2"}}
	pageMeta := &PaginationMeta{
		Page:       1,
		PerPage:    2,
		TotalItems: 10,
		TotalPages: 5,
		HasNext:    true,
		HasPrev:    false,
	}

	err := Paginated(cPage, items, pageMeta)
	if err != nil {
		t.Fatalf("Paginated returned error: %v", err)
	}

	var parsedPage Envelope[[]sampleUser]
	if err := json.Unmarshal(recPage.Body.Bytes(), &parsedPage); err != nil {
		t.Fatalf("failed to unmarshal paginated envelope: %v", err)
	}
	if len(parsedPage.Data) != 2 || parsedPage.Pagination.TotalItems != 10 {
		t.Errorf("unexpected paginated envelope: %+v", parsedPage)
	}
	if parsedPage.Links == nil || !strings.Contains(parsedPage.Links.Next, "page=2") {
		t.Errorf("expected next link page=2, got %+v", parsedPage.Links)
	}
	if recPage.Header().Get("Link") == "" {
		t.Errorf("expected RFC 5988 Link header")
	}

	// 2. CursorPaginated Helper
	recCursor := httptest.NewRecorder()
	cCursor := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/events", nil), recCursor)
	cursorMeta := &CursorMeta{
		Cursor:     "cur-1",
		NextCursor: "cur-2",
		Limit:      10,
		HasMore:    true,
	}

	errCursor := CursorPaginated(cCursor, items, cursorMeta)
	if errCursor != nil {
		t.Fatalf("CursorPaginated returned error: %v", errCursor)
	}

	var parsedCursor Envelope[[]sampleUser]
	if err := json.Unmarshal(recCursor.Body.Bytes(), &parsedCursor); err != nil {
		t.Fatalf("failed to unmarshal cursor envelope: %v", err)
	}
	if parsedCursor.Cursor.NextCursor != "cur-2" {
		t.Errorf("expected next cursor cur-2, got %+v", parsedCursor.Cursor)
	}
}

func TestHelpers_ErrorAndDurationMiddleware(t *testing.T) {
	e := echo.New()
	mw := Middleware()

	handler := mw(func(c *echo.Context) error {
		time.Sleep(10 * time.Millisecond)
		return OK(c, sampleUser{ID: 99, Name: "Delayed"})
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/delayed", nil)
	c := e.NewContext(req, rec)

	if err := handler(c); err != nil {
		t.Fatalf("handler failed: %v", err)
	}

	var parsed Envelope[sampleUser]
	if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if parsed.Meta == nil || parsed.Meta.Duration == "" {
		t.Errorf("expected duration to be recorded in envelope meta")
	}

	// Test Error helper
	recErr := httptest.NewRecorder()
	cErr := e.NewContext(httptest.NewRequest(http.MethodGet, "/api/fail", nil), recErr)
	cErr.Response().Header().Set(echo.HeaderXRequestID, "req-fail-99")

	rawErr := errors.New("something went wrong")
	errOut := Error(cErr, rawErr)
	if errOut != nil {
		t.Fatalf("Error helper returned error: %v", errOut)
	}
	if recErr.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", recErr.Code)
	}
}
