// Package cache is an identity-bound response cache for MCP list/read results.
//
// MCP 2026-07-28 lets servers attach `ttlMs` and `cacheScope` ("public" |
// "private") to list and read results. MCP-2026-008 showed that a malicious
// server can mark a poisoned response "public" and a shared gateway will fan
// it out to every user. Shield therefore:
//   - ALWAYS keys entries on (server identity, caller identity, method, params);
//     "public" is treated as a hint about reusability, never as permission to
//     share across callers;
//   - refuses to store any payload carrying `instructions` that asks for
//     cacheScope=public;
//   - caps TTLs so a poisoned entry cannot live for long.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

type Key struct {
	ServerID string // verified backend identity from config, NOT self-reported serverInfo
	CallerID string // Principal.CallerKey()
	Method   string
	Params   []byte
}

func (k Key) String() string {
	h := sha256.New()
	for _, p := range [][]byte{[]byte(k.ServerID), []byte(k.CallerID), []byte(k.Method), k.Params} {
		h.Write(p)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

type entry struct {
	body    []byte
	expires time.Time
}

type Cache struct {
	mu         sync.Mutex
	items      map[string]entry
	maxTTL     time.Duration
	maxEntries int
	now        func() time.Time
}

func New(maxTTL time.Duration, maxEntries int) *Cache {
	if maxTTL <= 0 {
		maxTTL = 5 * time.Minute
	}
	if maxEntries <= 0 {
		maxEntries = 10000
	}
	return &Cache{items: map[string]entry{}, maxTTL: maxTTL, maxEntries: maxEntries, now: time.Now}
}

func (c *Cache) Get(k Key) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[k.String()]
	if !ok || c.now().After(e.expires) {
		delete(c.items, k.String())
		return nil, false
	}
	return e.body, true
}

// Put stores result body under k if the result's own cache hints allow it.
// It returns whether the entry was stored and, if not, why.
func (c *Cache) Put(k Key, body []byte, result map[string]any) (bool, string) {
	ttlMs, _ := result["ttlMs"].(float64)
	scope, _ := result["cacheScope"].(string)
	if ttlMs <= 0 {
		return false, "no ttlMs"
	}
	if _, hasInstr := result["instructions"]; hasInstr && scope == "public" {
		return false, "instructions present with cacheScope=public"
	}
	ttl := time.Duration(ttlMs) * time.Millisecond
	if ttl > c.maxTTL {
		ttl = c.maxTTL
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.items) >= c.maxEntries {
		c.evictExpiredLocked()
		if len(c.items) >= c.maxEntries {
			return false, "cache full"
		}
	}
	c.items[k.String()] = entry{body: body, expires: c.now().Add(ttl)}
	return true, ""
}

func (c *Cache) evictExpiredLocked() {
	now := c.now()
	for k, e := range c.items {
		if now.After(e.expires) {
			delete(c.items, k)
		}
	}
}

func (c *Cache) Len() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.items) }
