package filetest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"strconv"
	"strings"
	"testing"

	"ztatic-go-framework/response"
)

// Client is a fluent test client designed for testing file upload and download operations
// against an http.Handler (e.g. *ztatic.Engine, *echo.Echo, or standard http.Handler).
type Client struct {
	handler        http.Handler
	defaultHeaders map[string]string
	defaultCookies []*http.Cookie
}

// NewClient initializes a testing client for the given HTTP handler.
func NewClient(handler http.Handler) *Client {
	return &Client{
		handler:        handler,
		defaultHeaders: make(map[string]string),
	}
}

// SetDefaultHeader sets a header that will be sent with every request created by this client.
func (c *Client) SetDefaultHeader(key, value string) *Client {
	c.defaultHeaders[key] = value
	return c
}

// SetBearerToken sets an Authorization: Bearer <token> header for all subsequent requests.
func (c *Client) SetBearerToken(token string) *Client {
	return c.SetDefaultHeader("Authorization", "Bearer "+token)
}

// SetCookie adds a cookie to all subsequent requests created by this client.
func (c *Client) SetCookie(cookie *http.Cookie) *Client {
	c.defaultCookies = append(c.defaultCookies, cookie)
	return c
}

// NewUpload creates an upload request builder for POST requests to the given URL.
func (c *Client) NewUpload(url string) *UploadRequestBuilder {
	return &UploadRequestBuilder{
		client:  c,
		url:     url,
		method:  http.MethodPost,
		fields:  make(map[string]string),
		headers: make(map[string]string),
	}
}

// Post is a convenience alias for NewUpload(url).
func (c *Client) Post(url string) *UploadRequestBuilder {
	return c.NewUpload(url)
}

// Put creates an upload request builder targeting HTTP PUT.
func (c *Client) Put(url string) *UploadRequestBuilder {
	b := c.NewUpload(url)
	b.method = http.MethodPut
	return b
}

// Patch creates an upload request builder targeting HTTP PATCH.
func (c *Client) Patch(url string) *UploadRequestBuilder {
	b := c.NewUpload(url)
	b.method = http.MethodPatch
	return b
}

// NewDownload creates a download request builder for testing file serving and Range streaming.
func (c *Client) NewDownload(url string) *DownloadRequestBuilder {
	return &DownloadRequestBuilder{
		client:  c,
		url:     url,
		headers: make(map[string]string),
	}
}

// Get executes a GET request against the target URL and returns the Response wrapper.
func (c *Client) Get(url string) *Response {
	return c.NewDownload(url).Send()
}

// UploadAttachment describes a file attachment in a multipart upload request.
type UploadAttachment struct {
	FieldName   string
	Filename    string
	ContentType string
	Reader      io.Reader
	Size        int64
}

// UploadRequestBuilder provides a fluent builder for assembling multipart HTTP upload requests.
type UploadRequestBuilder struct {
	client      *Client
	url         string
	method      string
	fields      map[string]string
	attachments []UploadAttachment
	headers     map[string]string
	cookies     []*http.Cookie
	ctx         context.Context
}

// Method sets the HTTP method (e.g. POST, PUT, PATCH).
func (b *UploadRequestBuilder) Method(method string) *UploadRequestBuilder {
	b.method = method
	return b
}

// Field adds a text form field to the multipart payload.
func (b *UploadRequestBuilder) Field(name, value string) *UploadRequestBuilder {
	b.fields[name] = value
	return b
}

// Fields adds multiple text form fields to the multipart payload.
func (b *UploadRequestBuilder) Fields(fields map[string]string) *UploadRequestBuilder {
	for k, v := range fields {
		b.fields[k] = v
	}
	return b
}

// Attach attaches a FileFixture (e.g. fixtures.PNG, fixtures.PDF) under the given form field.
func (b *UploadRequestBuilder) Attach(fieldName string, fixture FileFixture) *UploadRequestBuilder {
	if fixture == nil {
		return b
	}
	b.attachments = append(b.attachments, UploadAttachment{
		FieldName:   fieldName,
		Filename:    fixture.Name(),
		ContentType: fixture.MIME(),
		Reader:      fixture.Reader(),
		Size:        fixture.Size(),
	})
	return b
}

// AttachBytes attaches in-memory bytes under the given form field name.
func (b *UploadRequestBuilder) AttachBytes(fieldName, filename string, data []byte, contentType string) *UploadRequestBuilder {
	b.attachments = append(b.attachments, UploadAttachment{
		FieldName:   fieldName,
		Filename:    filename,
		ContentType: contentType,
		Reader:      bytes.NewReader(data),
		Size:        int64(len(data)),
	})
	return b
}

// AttachReader attaches an arbitrary io.Reader stream under the given form field name.
func (b *UploadRequestBuilder) AttachReader(fieldName, filename string, r io.Reader, size int64, contentType string) *UploadRequestBuilder {
	b.attachments = append(b.attachments, UploadAttachment{
		FieldName:   fieldName,
		Filename:    filename,
		ContentType: contentType,
		Reader:      r,
		Size:        size,
	})
	return b
}

// Header sets a single HTTP header for this upload request.
func (b *UploadRequestBuilder) Header(key, value string) *UploadRequestBuilder {
	b.headers[key] = value
	return b
}

// Headers adds multiple HTTP headers for this upload request.
func (b *UploadRequestBuilder) Headers(headers map[string]string) *UploadRequestBuilder {
	for k, v := range headers {
		b.headers[k] = v
	}
	return b
}

// WithBearerToken sets an Authorization: Bearer <token> header for this upload request.
func (b *UploadRequestBuilder) WithBearerToken(token string) *UploadRequestBuilder {
	return b.Header("Authorization", "Bearer "+token)
}

// WithCookie attaches an HTTP cookie to this upload request.
func (b *UploadRequestBuilder) WithCookie(cookie *http.Cookie) *UploadRequestBuilder {
	b.cookies = append(b.cookies, cookie)
	return b
}

// WithContext sets the context.Context for this request.
func (b *UploadRequestBuilder) WithContext(ctx context.Context) *UploadRequestBuilder {
	b.ctx = ctx
	return b
}

// Send builds and executes the multipart request, returning the Response wrapper.
func (b *UploadRequestBuilder) Send() *Response {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Write standard form fields
	for k, v := range b.fields {
		_ = writer.WriteField(k, v)
	}

	// Write file attachments
	for _, att := range b.attachments {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`, att.FieldName, att.Filename))
		if att.ContentType != "" {
			h.Set("Content-Type", att.ContentType)
		}
		part, err := writer.CreatePart(h)
		if err != nil {
			panic(fmt.Sprintf("filetest: failed to create multipart part: %v", err))
		}
		if att.Reader != nil {
			if _, err := io.Copy(part, att.Reader); err != nil {
				panic(fmt.Sprintf("filetest: failed to write attachment %s: %v", att.Filename, err))
			}
		}
	}

	_ = writer.Close()

	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	req := httptest.NewRequest(b.method, b.url, body).WithContext(ctx)
	req.Header.Set("Content-Type", writer.FormDataContentType())

	// Apply default client headers
	for k, v := range b.client.defaultHeaders {
		req.Header.Set(k, v)
	}
	// Apply request-specific headers
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}

	// Apply cookies
	for _, c := range b.client.defaultCookies {
		req.AddCookie(c)
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	b.client.handler.ServeHTTP(rec, req)

	return newResponse(rec)
}

// SendMethod overrides the method and executes the request.
func (b *UploadRequestBuilder) SendMethod(method string) *Response {
	b.method = method
	return b.Send()
}

// DownloadRequestBuilder provides a fluent builder for file retrieval and HTTP 206 Range requests.
type DownloadRequestBuilder struct {
	client  *Client
	url     string
	headers map[string]string
	cookies []*http.Cookie
	ctx     context.Context
}

// Header sets a single HTTP header.
func (b *DownloadRequestBuilder) Header(key, value string) *DownloadRequestBuilder {
	b.headers[key] = value
	return b
}

// Headers adds multiple HTTP headers.
func (b *DownloadRequestBuilder) Headers(headers map[string]string) *DownloadRequestBuilder {
	for k, v := range headers {
		b.headers[k] = v
	}
	return b
}

// WithBearerToken sets an Authorization: Bearer <token> header.
func (b *DownloadRequestBuilder) WithBearerToken(token string) *DownloadRequestBuilder {
	return b.Header("Authorization", "Bearer "+token)
}

// WithCookie attaches an HTTP cookie.
func (b *DownloadRequestBuilder) WithCookie(cookie *http.Cookie) *DownloadRequestBuilder {
	b.cookies = append(b.cookies, cookie)
	return b
}

// WithContext sets the request context.Context.
func (b *DownloadRequestBuilder) WithContext(ctx context.Context) *DownloadRequestBuilder {
	b.ctx = ctx
	return b
}

// WithRange requests a specific byte range (e.g. Range: bytes=0-1023).
func (b *DownloadRequestBuilder) WithRange(start, end int64) *DownloadRequestBuilder {
	return b.Header("Range", fmt.Sprintf("bytes=%d-%d", start, end))
}

// WithRangeFrom requests all bytes from start to EOF (e.g. Range: bytes=1024-).
func (b *DownloadRequestBuilder) WithRangeFrom(start int64) *DownloadRequestBuilder {
	return b.Header("Range", fmt.Sprintf("bytes=%d-", start))
}

// WithRangeSuffix requests the last suffixLength bytes (e.g. Range: bytes=-500).
func (b *DownloadRequestBuilder) WithRangeSuffix(suffixLength int64) *DownloadRequestBuilder {
	return b.Header("Range", fmt.Sprintf("bytes=-%d", suffixLength))
}

// WithETag sends an If-None-Match header for cache validation.
func (b *DownloadRequestBuilder) WithETag(etag string) *DownloadRequestBuilder {
	if !strings.HasPrefix(etag, `"`) {
		etag = `"` + etag + `"`
	}
	return b.Header("If-None-Match", etag)
}

// Send executes the GET download request against the handler.
func (b *DownloadRequestBuilder) Send() *Response {
	ctx := b.ctx
	if ctx == nil {
		ctx = context.Background()
	}

	req := httptest.NewRequest(http.MethodGet, b.url, nil).WithContext(ctx)

	for k, v := range b.client.defaultHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range b.headers {
		req.Header.Set(k, v)
	}

	for _, c := range b.client.defaultCookies {
		req.AddCookie(c)
	}
	for _, c := range b.cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	b.client.handler.ServeHTTP(rec, req)

	return newResponse(rec)
}

// Response wraps *httptest.ResponseRecorder with file-specific inspection helpers and fluent assertions.
type Response struct {
	Recorder   *httptest.ResponseRecorder
	StatusCode int
}

func newResponse(rec *httptest.ResponseRecorder) *Response {
	return &Response{
		Recorder:   rec,
		StatusCode: rec.Code,
	}
}

// BodyBytes returns the raw response body bytes.
func (r *Response) BodyBytes() []byte {
	return r.Recorder.Body.Bytes()
}

// BodyString returns the response body as a string.
func (r *Response) BodyString() string {
	return r.Recorder.Body.String()
}

// Header returns the first value associated with the given header key.
func (r *Response) Header(key string) string {
	return r.Recorder.Header().Get(key)
}

// ContentType returns the MIME media type without parameters (e.g. "image/png").
func (r *Response) ContentType() string {
	raw := r.Header("Content-Type")
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return raw
	}
	return mediaType
}

// RawContentType returns the unparsed Content-Type header value.
func (r *Response) RawContentType() string {
	return r.Header("Content-Type")
}

// ContentLength returns the parsed Content-Length header or length of the response body.
func (r *Response) ContentLength() int64 {
	raw := r.Header("Content-Length")
	if raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return n
		}
	}
	return int64(r.Recorder.Body.Len())
}

// ContentRange parses the Content-Range header (e.g. "bytes 0-1023/5000")
// and returns start, end, total, or error.
func (r *Response) ContentRange() (start, end, total int64, err error) {
	raw := r.Header("Content-Range")
	if raw == "" {
		return 0, 0, 0, fmt.Errorf("filetest: missing Content-Range header")
	}

	// format: "bytes <start>-<end>/<total>"
	raw = strings.TrimPrefix(raw, "bytes ")
	parts := strings.Split(raw, "/")
	if len(parts) != 2 {
		return 0, 0, 0, fmt.Errorf("filetest: invalid Content-Range header format: %s", raw)
	}

	rangeParts := strings.Split(parts[0], "-")
	if len(rangeParts) != 2 {
		return 0, 0, 0, fmt.Errorf("filetest: invalid range segment: %s", parts[0])
	}

	start, err = strconv.ParseInt(rangeParts[0], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
	end, err = strconv.ParseInt(rangeParts[1], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}
	total, err = strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return 0, 0, 0, err
	}

	return start, end, total, nil
}

// Filename extracts the target filename from the Content-Disposition header.
func (r *Response) Filename() string {
	disposition := r.Header("Content-Disposition")
	if disposition == "" {
		return ""
	}
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	if filename, ok := params["filename*"]; ok {
		// RFC 5987 / RFC 6266 encoding
		parts := strings.SplitN(filename, "''", 2)
		if len(parts) == 2 {
			return parts[1]
		}
	}
	return params["filename"]
}

// IsAttachment returns true if Content-Disposition starts with "attachment".
func (r *Response) IsAttachment() bool {
	return strings.HasPrefix(strings.ToLower(r.Header("Content-Disposition")), "attachment")
}

// IsInline returns true if Content-Disposition starts with "inline".
func (r *Response) IsInline() bool {
	return strings.HasPrefix(strings.ToLower(r.Header("Content-Disposition")), "inline")
}

// ETag returns the ETag header value with quotes stripped.
func (r *Response) ETag() string {
	raw := r.Header("ETag")
	return strings.Trim(raw, `"`)
}

// SHA256 computes and returns the hex-encoded SHA-256 checksum of the response body.
func (r *Response) SHA256() string {
	h := sha256.Sum256(r.BodyBytes())
	return hex.EncodeToString(h[:])
}

// JSON deserializes the response body into target.
func (r *Response) JSON(target any) error {
	return json.Unmarshal(r.BodyBytes(), target)
}

// Envelope deserializes the response body into a generic Ztatic Response Envelope.
func (r *Response) Envelope() (*response.Envelope[any], error) {
	var env response.Envelope[any]
	if err := json.Unmarshal(r.BodyBytes(), &env); err != nil {
		return nil, err
	}
	return &env, nil
}

// Fluent assertions on *Response

// AssertStatus verifies that the response status code equals expected.
func (r *Response) AssertStatus(t testing.TB, expected int) *Response {
	t.Helper()
	if r.StatusCode != expected {
		t.Fatalf("expected HTTP status %d, got %d. Body: %s", expected, r.StatusCode, r.BodyString())
	}
	return r
}

// AssertOK verifies HTTP 200 OK.
func (r *Response) AssertOK(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusOK)
}

// AssertCreated verifies HTTP 201 Created.
func (r *Response) AssertCreated(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusCreated)
}

// AssertNoContent verifies HTTP 204 No Content.
func (r *Response) AssertNoContent(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusNoContent)
}

// AssertBadRequest verifies HTTP 400 Bad Request.
func (r *Response) AssertBadRequest(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusBadRequest)
}

// AssertUnauthorized verifies HTTP 401 Unauthorized.
func (r *Response) AssertUnauthorized(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusUnauthorized)
}

// AssertForbidden verifies HTTP 403 Forbidden.
func (r *Response) AssertForbidden(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusForbidden)
}

// AssertNotFound verifies HTTP 404 Not Found.
func (r *Response) AssertNotFound(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusNotFound)
}

// AssertFileTooLarge verifies HTTP 413 Payload / Entity Too Large.
func (r *Response) AssertFileTooLarge(t testing.TB) *Response {
	return r.AssertStatus(t, http.StatusRequestEntityTooLarge)
}

// AssertDownloaded asserts that the response is an attachment download with the expected filename.
func (r *Response) AssertDownloaded(t testing.TB, expectedFilename string) *Response {
	t.Helper()
	if !r.IsAttachment() {
		t.Errorf("expected Content-Disposition to be 'attachment', got %q", r.Header("Content-Disposition"))
	}
	if expectedFilename != "" && r.Filename() != expectedFilename {
		t.Errorf("expected download filename %q, got %q", expectedFilename, r.Filename())
	}
	return r
}

// AssertInline asserts that the response is served inline with the expected filename.
func (r *Response) AssertInline(t testing.TB, expectedFilename string) *Response {
	t.Helper()
	if !r.IsInline() {
		t.Errorf("expected Content-Disposition to be 'inline', got %q", r.Header("Content-Disposition"))
	}
	if expectedFilename != "" && r.Filename() != expectedFilename {
		t.Errorf("expected inline filename %q, got %q", expectedFilename, r.Filename())
	}
	return r
}

// AssertContentType asserts that the Content-Type header matches expected MIME.
func (r *Response) AssertContentType(t testing.TB, expectedMIME string) *Response {
	t.Helper()
	if r.ContentType() != expectedMIME {
		t.Errorf("expected Content-Type %q, got %q", expectedMIME, r.ContentType())
	}
	return r
}

// AssertContentLength asserts the Content-Length of the response body.
func (r *Response) AssertContentLength(t testing.TB, expectedLength int64) *Response {
	t.Helper()
	if r.ContentLength() != expectedLength {
		t.Errorf("expected Content-Length %d, got %d", expectedLength, r.ContentLength())
	}
	return r
}

// AssertSHA256 asserts that the response body's SHA-256 matches the expected hash.
func (r *Response) AssertSHA256(t testing.TB, expectedHash string) *Response {
	t.Helper()
	if r.SHA256() != expectedHash {
		t.Errorf("expected body SHA256 %q, got %q", expectedHash, r.SHA256())
	}
	return r
}

// AssertContentEquals asserts that the response body bytes match expectedBytes.
func (r *Response) AssertContentEquals(t testing.TB, expectedBytes []byte) *Response {
	t.Helper()
	if !bytes.Equal(r.BodyBytes(), expectedBytes) {
		t.Errorf("response body does not match expected bytes (len %d vs %d)", len(r.BodyBytes()), len(expectedBytes))
	}
	return r
}

// AssertBodyContains asserts that the response body contains substr.
func (r *Response) AssertBodyContains(t testing.TB, substr string) *Response {
	t.Helper()
	if !strings.Contains(r.BodyString(), substr) {
		t.Errorf("expected response body to contain %q, but body was: %s", substr, r.BodyString())
	}
	return r
}

// AssertNoSniff asserts that X-Content-Type-Options: nosniff is set.
func (r *Response) AssertNoSniff(t testing.TB) *Response {
	t.Helper()
	if r.Header("X-Content-Type-Options") != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got %q", r.Header("X-Content-Type-Options"))
	}
	return r
}

// AssertSandboxedCSP asserts that Content-Security-Policy contains 'sandbox' and 'default-src \'none\''.
func (r *Response) AssertSandboxedCSP(t testing.TB) *Response {
	t.Helper()
	csp := r.Header("Content-Security-Policy")
	if !strings.Contains(csp, "sandbox") || !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("expected sandboxed Content-Security-Policy, got %q", csp)
	}
	return r
}

// AssertAcceptRanges asserts that the server advertises Accept-Ranges: bytes.
func (r *Response) AssertAcceptRanges(t testing.TB) *Response {
	t.Helper()
	if r.Header("Accept-Ranges") != "bytes" {
		t.Errorf("expected Accept-Ranges: bytes, got %q", r.Header("Accept-Ranges"))
	}
	return r
}

// AssertPartialContent asserts HTTP 206 Partial Content and valid Content-Range header.
func (r *Response) AssertPartialContent(t testing.TB, expectedStart, expectedEnd, expectedTotal int64) *Response {
	t.Helper()
	r.AssertStatus(t, http.StatusPartialContent)
	start, end, total, err := r.ContentRange()
	if err != nil {
		t.Fatalf("failed to parse Content-Range: %v", err)
	}
	if start != expectedStart || end != expectedEnd || total != expectedTotal {
		t.Errorf("expected Content-Range bytes %d-%d/%d, got %d-%d/%d",
			expectedStart, expectedEnd, expectedTotal, start, end, total)
	}
	return r
}
