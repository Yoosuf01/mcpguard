// Package health provides /healthz (liveness) and /readyz (readiness) HTTP
// handlers following the Kubernetes probe convention.
package health

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

// CheckFn returns a non-nil error when the subsystem is unhealthy.
type CheckFn func() error

// Checker holds named readiness checks polled on every /readyz request.
type Checker struct {
	mu     sync.RWMutex
	checks map[string]CheckFn
}

// New creates an empty Checker.
func New() *Checker { return &Checker{checks: make(map[string]CheckFn)} }

// Register adds or replaces a named check.
func (c *Checker) Register(name string, fn CheckFn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.checks[name] = fn
}

// LivenessHandler returns 200 OK as long as the process is running.
func LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"ts":     time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// ReadinessHandler runs all checks; returns 503 with a degraded body if any fail.
func (c *Checker) ReadinessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c.mu.RLock()
		checks := make(map[string]CheckFn, len(c.checks))
		for k, v := range c.checks { checks[k] = v }
		c.mu.RUnlock()

		results := make(map[string]string, len(checks))
		allOK := true
		for name, fn := range checks {
			if err := fn(); err != nil {
				results[name] = err.Error()
				allOK = false
			} else {
				results[name] = "ok"
			}
		}
		body := map[string]any{
			"status": "ok",
			"checks": results,
			"ts":     time.Now().UTC().Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		if !allOK {
			body["status"] = "degraded"
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(body)
	}
}
