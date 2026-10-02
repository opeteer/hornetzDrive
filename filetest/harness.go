package filetest

import (
	"net/http"
	"testing"

	"ztatic-go-framework/upload"
)

// Harness bundles Client, MockStorage, and MockScanner into an integrated testing sandbox.
type Harness struct {
	t       testing.TB
	Client  *Client
	Storage *MockStorage
	Scanner *MockScanner
}

// NewHarness creates an integrated testing harness for the given HTTP handler.
func NewHarness(t testing.TB, handler http.Handler) *Harness {
	store := NewMockStorage()
	scanner := NewMockScanner()
	client := NewClient(handler)

	return &Harness{
		t:       t,
		Client:  client,
		Storage: store,
		Scanner: scanner,
	}
}

// NewTestManager creates a configured *upload.Manager pre-wired with MockStorage and MockScanner.
// Returns the manager, mock storage, and mock scanner for direct spy/stub access.
func NewTestManager(options ...func(*upload.Config)) (*upload.Manager, *MockStorage, *MockScanner) {
	store := NewMockStorage()
	scanner := NewMockScanner()

	cfg := upload.DefaultConfig()
	cfg.Storage = store
	cfg.Scanner = scanner

	for _, opt := range options {
		opt(&cfg)
	}

	mgr, err := upload.NewManager(cfg)
	if err != nil {
		panic("filetest: failed to construct test manager: " + err.Error())
	}

	return mgr, store, scanner
}
