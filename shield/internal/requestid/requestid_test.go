package requestid_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/requestid"
)

func TestGeneratesID(t *testing.T) {
	var got string
	h := requestid.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = requestid.FromContext(r.Context())
	}))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/mcp", nil))
	if got == "" {
		t.Fatal("expected a request ID to be generated")
	}
}

func TestPreservesExistingID(t *testing.T) {
	const want = "my-trace-id-123"
	var got string
	h := requestid.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = requestid.FromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("X-Request-ID", want)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != want {
		t.Fatalf("want %q got %q", want, got)
	}
}

func TestResponseHeaderSet(t *testing.T) {
	h := requestid.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Header().Get("X-Request-ID") == "" {
		t.Fatal("X-Request-ID must be echoed in response")
	}
}
