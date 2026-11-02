package state

import (
	"context"
	"sync"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
)

// MemoryCounters implements CounterStore with TTL-based session eviction to prevent unbounded memory growth.
type MemoryCounters struct {
	mu       sync.Mutex
	steps    map[string]stepEntry
	window   map[string]rateEntry
	ttl      time.Duration
	now      func() time.Time
	lastEvict time.Time
}

type stepEntry struct {
	count    int
	lastSeen time.Time
}

type rateEntry struct {
	start    time.Time
	count    int
	lastSeen time.Time
}

func NewMemoryCounters(ttl time.Duration) *MemoryCounters {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	return &MemoryCounters{
		steps:     make(map[string]stepEntry),
		window:    make(map[string]rateEntry),
		ttl:       ttl,
		now:       time.Now,
		lastEvict: time.Now(),
	}
}

func (c *MemoryCounters) Step(_ context.Context, session string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maybeEvictLocked()

	now := c.now()
	entry := c.steps[session]
	entry.count++
	entry.lastSeen = now
	c.steps[session] = entry
	return entry.count, nil
}

func (c *MemoryCounters) Rate(_ context.Context, session string) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.maybeEvictLocked()

	now := c.now()
	w := c.window[session]
	if now.Sub(w.start) >= time.Minute {
		w = rateEntry{start: now}
	}
	w.count++
	w.lastSeen = now
	c.window[session] = w
	return w.count, nil
}

func (c *MemoryCounters) Reset(_ context.Context, session string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.steps, session)
	delete(c.window, session)
	return nil
}

func (c *MemoryCounters) maybeEvictLocked() {
	now := c.now()
	if now.Sub(c.lastEvict) < 5*time.Minute {
		return
	}
	c.lastEvict = now
	for k, v := range c.steps {
		if now.Sub(v.lastSeen) > c.ttl {
			delete(c.steps, k)
		}
	}
	for k, v := range c.window {
		if now.Sub(v.lastSeen) > c.ttl {
			delete(c.window, k)
		}
	}
}

// MemoryRevocations stores revoked session IDs in memory with optional TTL eviction.
type MemoryRevocations struct {
	mu  sync.RWMutex
	m   map[string]time.Time
	ttl time.Duration
}

func NewMemoryRevocations(ttl time.Duration) *MemoryRevocations {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &MemoryRevocations{m: make(map[string]time.Time), ttl: ttl}
}

func (r *MemoryRevocations) IsRevoked(_ context.Context, sid string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	revTime, ok := r.m[sid]
	if !ok {
		return false
	}
	return time.Since(revTime) < r.ttl
}

func (r *MemoryRevocations) Revoke(_ context.Context, sid string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[sid] = time.Now()
}

// MemoryPins implements PinStore for in-memory tool hash digests.
type MemoryPins struct {
	mu sync.RWMutex
	m  map[string]string
}

func NewMemoryPins() *MemoryPins {
	return &MemoryPins{m: make(map[string]string)}
}

func (p *MemoryPins) Get(key string) (string, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	val, ok := p.m[key]
	return val, ok
}

func (p *MemoryPins) Set(key, digest string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.m[key] = digest
}

// MemoryHITLStore wraps hitl.Store to satisfy HITLStore interface.
type MemoryHITLStore struct {
	*hitl.Store
}

func NewMemoryHITLStore(ttl time.Duration) *MemoryHITLStore {
	return &MemoryHITLStore{Store: hitl.NewStore(ttl)}
}
