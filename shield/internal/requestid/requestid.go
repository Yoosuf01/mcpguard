// Package requestid injects a unique X-Request-ID into every HTTP request.
package requestid

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

type ctxKey struct{}

// Middleware reads X-Request-ID from the incoming request header; if absent
// it generates a crypto-random 16-byte ID and sets it on both request and response.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newID()
		}
		r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, id))
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r)
	})
}

// FromContext extracts the request ID from ctx; returns "" if not set.
func FromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
