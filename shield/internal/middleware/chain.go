// Package middleware provides a composable HTTP middleware chain builder.
package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

// Func is a standard middleware function signature.
type Func func(http.Handler) http.Handler

// Chain holds an ordered list of middlewares.
type Chain struct{ fns []Func }

// New creates a Chain.
func New(fns ...Func) Chain { return Chain{fns: append([]Func{}, fns...)} }

// Append returns a new Chain with extra middlewares appended.
func (c Chain) Append(fns ...Func) Chain {
	out := make([]Func, len(c.fns)+len(fns))
	copy(out, c.fns)
	copy(out[len(c.fns):], fns)
	return Chain{fns: out}
}

// Then wraps h with all middlewares in declaration order.
func (c Chain) Then(h http.Handler) http.Handler {
	for i := len(c.fns) - 1; i >= 0; i-- {
		h = c.fns[i](h)
	}
	return h
}

// Recover catches panics, logs them, and responds 500 so the process keeps running.
func Recover(log *slog.Logger) Func {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic in handler",
						"panic", rec,
						"stack", string(debug.Stack()),
					)
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// Timeout cancels the request context after d.
func Timeout(d time.Duration) Func {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), d)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CORS adds Access-Control headers for the given origin allowlist.
// Pass "*" in origins to allow any origin.
func CORS(origins []string) Func {
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		allowed[o] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if o := r.Header.Get("Origin"); allowed["*"] || allowed[o] {
				w.Header().Set("Access-Control-Allow-Origin", o)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
