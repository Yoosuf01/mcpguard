package middleware_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/middleware"
)

func TestChainOrder(t *testing.T) {
	var order []string
	mk := func(name string) middleware.Func {
		return func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, name+"-before")
				next.ServeHTTP(w, r)
				order = append(order, name+"-after")
			})
		}
	}
	h := middleware.New(mk("m1"), mk("m2")).Then(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order = append(order, "handler")
		}),
	)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	want := []string{"m1-before", "m2-before", "handler", "m2-after", "m1-after"}
	for i, s := range want {
		if order[i] != s {
			t.Errorf("[%d] got %q want %q", i, order[i], s)
		}
	}
}

func TestRecover(t *testing.T) {
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	h := middleware.New(middleware.Recover(log)).Then(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic("boom") }),
	)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", rec.Code)
	}
}

func TestTimeout(t *testing.T) {
	h := middleware.New(middleware.Timeout(10 * time.Millisecond)).Then(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }),
	)
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
}
