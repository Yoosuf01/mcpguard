// Package ratelimit provides a thread-safe sliding-window rate limiter.
// Each key (e.g. session ID) gets its own independent window, eliminating
// the "double-burst at window boundary" problem of fixed-window counters.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a sliding-window rate limiter.
type Limiter struct {
	mu       sync.Mutex
	wins     map[string]*window
	limit    int
	interval time.Duration
	now      func() time.Time
}

type window struct{ ts []time.Time }

// New creates a Limiter allowing at most limit events per interval per key.
func New(limit int, interval time.Duration) *Limiter {
	return &Limiter{
		wins:     make(map[string]*window),
		limit:    limit,
		interval: interval,
		now:      time.Now,
	}
}

// Allow returns true if key is within its rate limit.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.interval)
	w, ok := l.wins[key]
	if !ok {
		w = &window{}
		l.wins[key] = w
	}
	valid := w.ts[:0]
	for _, ts := range w.ts {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	w.ts = valid
	if len(w.ts) >= l.limit {
		return false
	}
	w.ts = append(w.ts, now)
	return true
}

// Reset clears the window for key.
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.wins, key)
	l.mu.Unlock()
}

// Remaining returns how many more events key can make in the current window.
func (l *Limiter) Remaining(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	cutoff := now.Add(-l.interval)
	w, ok := l.wins[key]
	if !ok {
		return l.limit
	}
	used := 0
	for _, ts := range w.ts {
		if ts.After(cutoff) {
			used++
		}
	}
	if r := l.limit - used; r > 0 {
		return r
	}
	return 0
}
