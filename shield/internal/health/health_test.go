package health_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/health"
)

func TestLiveness(t *testing.T) {
	rec := httptest.NewRecorder()
	health.LivenessHandler()(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestReadinessAllOK(t *testing.T) {
	c := health.New()
	c.Register("db", func() error { return nil })
	rec := httptest.NewRecorder()
	c.ReadinessHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
}

func TestReadinessFailing(t *testing.T) {
	c := health.New()
	c.Register("upstream", func() error { return errors.New("connection refused") })
	rec := httptest.NewRecorder()
	c.ReadinessHandler()(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
	var body map[string]any
	json.NewDecoder(rec.Body).Decode(&body)
	if body["status"] != "degraded" {
		t.Errorf("want degraded, got %v", body["status"])
	}
}
