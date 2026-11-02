package state

import (
	"context"
	"testing"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestMemoryCounters_Eviction(t *testing.T) {
	fakeNow := time.Now()
	mem := NewMemoryCounters(50 * time.Millisecond)
	mem.now = func() time.Time { return fakeNow }

	ctx := context.Background()
	_, _ = mem.Step(ctx, "sess_active")
	_, _ = mem.Step(ctx, "sess_stale")

	// Advance time past TTL
	fakeNow = fakeNow.Add(10 * time.Minute)
	// Access active session so eviction triggers
	mem.lastEvict = fakeNow.Add(-10 * time.Minute)
	_, _ = mem.Step(ctx, "sess_active")

	mem.mu.Lock()
	_, hasStale := mem.steps["sess_stale"]
	mem.mu.Unlock()

	if hasStale {
		t.Error("expected stale session to be evicted from memory")
	}
}

func TestMemoryRevocationsAndPins(t *testing.T) {
	ctx := context.Background()
	revs := NewMemoryRevocations(time.Hour)
	if revs.IsRevoked(ctx, "s1") {
		t.Error("expected not revoked initially")
	}
	revs.Revoke(ctx, "s1")
	if !revs.IsRevoked(ctx, "s1") {
		t.Error("expected revoked after Revoke()")
	}

	pins := NewMemoryPins()
	if _, ok := pins.Get("postgres:query"); ok {
		t.Error("expected pin not found initially")
	}
	pins.Set("postgres:query", "sha256:abc123")
	val, ok := pins.Get("postgres:query")
	if !ok || val != "sha256:abc123" {
		t.Errorf("expected sha256:abc123, got %s (ok=%v)", val, ok)
	}
}

func TestRedis_MultiReplicaCounters(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb1 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rdb2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb1.Close()
	defer rdb2.Close()

	replica1 := NewRedisCounters(rdb1, time.Hour)
	replica2 := NewRedisCounters(rdb2, time.Hour)
	ctx := context.Background()

	// Step on replica 1
	n1, err := replica1.Step(ctx, "session_shared")
	if err != nil || n1 != 1 {
		t.Fatalf("expected step 1 on replica1, got %d (err=%v)", n1, err)
	}

	// Step on replica 2 should increment to 2
	n2, err := replica2.Step(ctx, "session_shared")
	if err != nil || n2 != 2 {
		t.Fatalf("expected step 2 on replica2, got %d (err=%v)", n2, err)
	}

	// Rate limit shared across replicas
	r1, _ := replica1.Rate(ctx, "session_shared")
	r2, _ := replica2.Rate(ctx, "session_shared")
	if r1 != 1 || r2 != 2 {
		t.Errorf("expected shared rate window [1, 2], got [%d, %d]", r1, r2)
	}
}

func TestRedis_MultiReplicaRevocationsAndPins(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb1 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rdb2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb1.Close()
	defer rdb2.Close()

	rev1 := NewRedisRevocations(rdb1, time.Hour)
	rev2 := NewRedisRevocations(rdb2, time.Hour)
	ctx := context.Background()

	// Replica 2 checks before revocation
	if rev2.IsRevoked(ctx, "target_session") {
		t.Fatal("expected session not revoked initially")
	}

	// Replica 1 revokes
	rev1.Revoke(ctx, "target_session")

	// Replica 2 immediately sees revocation (kill-switch propagated)
	if !rev2.IsRevoked(ctx, "target_session") {
		t.Fatal("expected replica2 to instantly see revocation by replica1")
	}

	// Pins shared across replicas
	pins1 := NewRedisPins(rdb1)
	pins2 := NewRedisPins(rdb2)
	pins1.Set("server1:tool1", "hash_abc_456")
	val, ok := pins2.Get("server1:tool1")
	if !ok || val != "hash_abc_456" {
		t.Errorf("expected replica2 to see pin hash_abc_456, got %s (ok=%v)", val, ok)
	}
}

func TestRedis_MultiReplicaHITL(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb1 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rdb2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb1.Close()
	defer rdb2.Close()

	hitl1 := NewRedisHITLStore(rdb1, 15*time.Minute)
	hitl2 := NewRedisHITLStore(rdb2, 15*time.Minute)

	args := map[string]any{"account": "12345", "amount": 500}

	// Replica 1 parks approval
	allowed, req := hitl1.Check("sess_hitl", "agent_fin", "user_cfo", "bank/wire", args)
	if allowed || req.Status != hitl.Pending {
		t.Fatalf("expected pending approval on replica1")
	}

	// Replica 2 lists pending and approves
	pendingList := hitl2.List()
	if len(pendingList) == 0 {
		t.Fatal("expected replica2 to see pending approval in list")
	}
	approvedReq, ok := hitl2.Decide(req.ID, true)
	if !ok || approvedReq.Status != hitl.Approved {
		t.Fatalf("expected replica2 to approve successfully")
	}

	// Replica 1 receives the tool call retry and allows it ONCE
	allowedRetry, consumed := hitl1.Check("sess_hitl", "agent_fin", "user_cfo", "bank/wire", args)
	if !allowedRetry || consumed.Status != hitl.Used {
		t.Fatalf("expected replica1 to allow approved retry, got allowed=%v", allowedRetry)
	}

	// Second retry on replica 2 must require NEW approval (single-use invariant)
	secondAllowed, secondReq := hitl2.Check("sess_hitl", "agent_fin", "user_cfo", "bank/wire", args)
	if secondAllowed {
		t.Fatal("single-use invariant violated across replicas")
	}
	if secondReq.ID == req.ID {
		t.Fatal("expected new request ID for subsequent call")
	}
}
