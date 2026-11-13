package state

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestPubSubRevocations_MultiReplicaPush(t *testing.T) {
	mr := miniredis.RunT(t)

	rdb1 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rdb2 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	rdb3 := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb1.Close()
	defer rdb2.Close()
	defer rdb3.Close()

	ctx := context.Background()

	rep1, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{Client: rdb1, TTL: time.Hour})
	if err != nil {
		t.Fatalf("failed to create rep1: %v", err)
	}
	defer rep1.Close()

	rep2, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{Client: rdb2, TTL: time.Hour})
	if err != nil {
		t.Fatalf("failed to create rep2: %v", err)
	}
	defer rep2.Close()

	rep3, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{Client: rdb3, TTL: time.Hour})
	if err != nil {
		t.Fatalf("failed to create rep3: %v", err)
	}
	defer rep3.Close()

	targetSession := "sess_kill_target_001"

	// Initially neither replica sees targetSession as revoked
	if rep2.IsRevoked(ctx, targetSession) || rep3.IsRevoked(ctx, targetSession) {
		t.Fatal("expected targetSession to not be revoked initially")
	}

	// Replica 1 revokes the session
	rep1.Revoke(ctx, targetSession)

	// Wait for Pub/Sub delivery to rep2 and rep3 (should happen almost instantaneously)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if rep2.IsRevoked(ctx, targetSession) && rep3.IsRevoked(ctx, targetSession) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !rep2.IsRevoked(ctx, targetSession) {
		t.Errorf("replica 2 did not receive revocation for %s", targetSession)
	}
	if !rep3.IsRevoked(ctx, targetSession) {
		t.Errorf("replica 3 did not receive revocation for %s", targetSession)
	}

	// Verify local in-memory cache was populated on peer replicas
	if rep2.LocalSize() == 0 {
		t.Error("expected rep2 to have targetSession in local cache")
	}
	if rep3.LocalSize() == 0 {
		t.Error("expected rep3 to have targetSession in local cache")
	}
}

func TestPubSubRevocations_FallbackRedis(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	ctx := context.Background()
	store, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{Client: rdb, TTL: time.Hour})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Inject key directly into Redis as if written when this replica was offline
	coldSession := "sess_cold_boot_999"
	err = rdb.Set(ctx, "mcpguard:revoked:"+coldSession, "1", time.Hour).Err()
	if err != nil {
		t.Fatalf("failed to set redis key: %v", err)
	}

	if store.LocalSize() != 0 {
		t.Fatalf("expected 0 local entries before query, got %d", store.LocalSize())
	}

	// Querying IsRevoked should fall back to Redis, detect the revocation, and cache locally
	if !store.IsRevoked(ctx, coldSession) {
		t.Errorf("expected %s to be revoked via Redis fallback", coldSession)
	}

	if store.LocalSize() != 1 {
		t.Errorf("expected local cache to be populated after fallback, got size %d", store.LocalSize())
	}

	// Second query should hit local cache
	if !store.IsRevoked(ctx, coldSession) {
		t.Errorf("expected %s to be revoked on second check from cache", coldSession)
	}
}

func TestPubSubRevocations_RawStringAndJSONPayloads(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	ctx := context.Background()
	store, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{Client: rdb, TTL: time.Hour})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	// Publish raw string
	rawSid := "sess_raw_string_test"
	_ = rdb.Publish(ctx, DefaultRevocationChannel, rawSid).Err()

	// Publish JSON payload
	jsonSid := "sess_json_format_test"
	msg := RevocationMessage{
		SessionID: jsonSid,
		RevokedAt: time.Now(),
		Reason:    "compromised_key",
	}
	data, _ := json.Marshal(msg)
	_ = rdb.Publish(ctx, DefaultRevocationChannel, string(data)).Err()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if store.IsRevoked(ctx, rawSid) && store.IsRevoked(ctx, jsonSid) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	if !store.IsRevoked(ctx, rawSid) {
		t.Errorf("expected raw string session %s to be revoked", rawSid)
	}
	if !store.IsRevoked(ctx, jsonSid) {
		t.Errorf("expected json payload session %s to be revoked", jsonSid)
	}
}

func TestPubSubRevocations_EmptySession(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	ctx := context.Background()
	store, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{Client: rdb, TTL: time.Hour})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	store.Revoke(ctx, "")
	if store.IsRevoked(ctx, "") {
		t.Error("empty session ID must never be marked revoked")
	}
}

func TestPubSubRevocations_TTLExpiration(t *testing.T) {
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer rdb.Close()

	ctx := context.Background()
	shortTTL := 20 * time.Millisecond
	store, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{Client: rdb, TTL: shortTTL})
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	sid := "sess_expires_quickly"
	store.Revoke(ctx, sid)

	if !store.IsRevoked(ctx, sid) {
		t.Fatalf("expected %s to be revoked initially", sid)
	}

	// Advance miniredis clock and wait past TTL
	mr.FastForward(100 * time.Millisecond)
	time.Sleep(30 * time.Millisecond)

	if store.IsRevoked(ctx, sid) {
		t.Errorf("expected %s to no longer be revoked after TTL expiration", sid)
	}
}

func TestPubSubRevocations_ConcurrentStress(t *testing.T) {
	mr := miniredis.RunT(t)

	const replicaCount = 4
	const sessionsPerWorker = 25

	replicas := make([]*PubSubRedisRevocations, replicaCount)
	clients := make([]*redis.Client, replicaCount)

	for i := 0; i < replicaCount; i++ {
		clients[i] = redis.NewClient(&redis.Options{Addr: mr.Addr()})
		rep, err := NewPubSubRedisRevocations(PubSubRevocationsOptions{
			Client: clients[i],
			TTL:    time.Hour,
		})
		if err != nil {
			t.Fatalf("failed to create replica %d: %v", i, err)
		}
		replicas[i] = rep
		defer clients[i].Close()
		defer rep.Close()
	}

	var wg sync.WaitGroup
	ctx := context.Background()

	// Spin up concurrent writers across different replicas
	for i := 0; i < replicaCount; i++ {
		wg.Add(1)
		repIdx := i
		go func() {
			defer wg.Done()
			for j := 0; j < sessionsPerWorker; j++ {
				sid := fmt.Sprintf("sess_concurrent_%d_%d", repIdx, j)
				replicas[repIdx].Revoke(ctx, sid)
			}
		}()
	}

	// Concurrently read from all replicas
	for i := 0; i < replicaCount; i++ {
		wg.Add(1)
		repIdx := i
		go func() {
			defer wg.Done()
			for j := 0; j < sessionsPerWorker; j++ {
				sid := fmt.Sprintf("sess_concurrent_%d_%d", repIdx, j)
				_ = replicas[repIdx].IsRevoked(ctx, sid)
			}
		}()
	}

	wg.Wait()
}
