package cache

import (
	"testing"
	"time"
)

// A3 / MCP-2026-008: a poisoned "public" response fetched by client A must
// never be served to client B.
func TestCacheNeverCrossesCallers(t *testing.T) {
	c := New(time.Minute, 100)
	res := map[string]any{"ttlMs": float64(3600000), "cacheScope": "public", "tools": []any{}}
	a := Key{ServerID: "web", CallerID: "alice|bot|s1", Method: "tools/list"}
	b := Key{ServerID: "web", CallerID: "bob|bot|s2", Method: "tools/list"}
	if ok, why := c.Put(a, []byte(`{"tools":[]}`), res); !ok {
		t.Fatal(why)
	}
	if _, hit := c.Get(a); !hit {
		t.Fatal("same caller should hit")
	}
	if _, hit := c.Get(b); hit {
		t.Fatal("CROSS-CALLER LEAK: public scope must not share across identities")
	}
	// Same caller, different server identity => miss.
	if _, hit := c.Get(Key{ServerID: "trusted", CallerID: a.CallerID, Method: "tools/list"}); hit {
		t.Fatal("server identity must be part of the key")
	}
}

func TestCacheRefusesPublicInstructions(t *testing.T) {
	c := New(time.Minute, 100)
	res := map[string]any{"ttlMs": float64(60000), "cacheScope": "public", "instructions": "IMPORTANT OVERRIDE..."}
	ok, why := c.Put(Key{ServerID: "web", CallerID: "x", Method: "server/discover"}, []byte("{}"), res)
	if ok || why != "instructions present with cacheScope=public" {
		t.Fatalf("should refuse, got %v %q", ok, why)
	}
	if c.Len() != 0 {
		t.Fatal("nothing should be stored")
	}
}

func TestCacheTTLCapped(t *testing.T) {
	c := New(time.Second, 100)
	now := time.Now()
	c.now = func() time.Time { return now }
	k := Key{ServerID: "s", CallerID: "c", Method: "tools/list"}
	c.Put(k, []byte("{}"), map[string]any{"ttlMs": float64(86400000)})
	c.now = func() time.Time { return now.Add(2 * time.Second) }
	if _, hit := c.Get(k); hit {
		t.Fatal("TTL must be capped at maxTTL")
	}
}
