package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
	"github.com/redis/go-redis/v9"
)

type RedisCounters struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRedisCounters(client *redis.Client, ttl time.Duration) *RedisCounters {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &RedisCounters{client: client, ttl: ttl}
}

func (r *RedisCounters) Step(ctx context.Context, session string) (int, error) {
	key := "mcpguard:steps:" + session
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, r.ttl)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return int(incr.Val()), nil
}

func (r *RedisCounters) Rate(ctx context.Context, session string) (int, error) {
	minuteBucket := time.Now().Unix() / 60
	key := fmt.Sprintf("mcpguard:rate:%s:%d", session, minuteBucket)
	pipe := r.client.Pipeline()
	incr := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, 120*time.Second)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, err
	}
	return int(incr.Val()), nil
}

func (r *RedisCounters) Reset(ctx context.Context, session string) error {
	stepKey := "mcpguard:steps:" + session
	return r.client.Del(ctx, stepKey).Err()
}

type RedisRevocations struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRedisRevocations(client *redis.Client, ttl time.Duration) *RedisRevocations {
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	return &RedisRevocations{client: client, ttl: ttl}
}

func (r *RedisRevocations) IsRevoked(ctx context.Context, sid string) bool {
	key := "mcpguard:revoked:" + sid
	val, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false
	}
	return val > 0
}

func (r *RedisRevocations) Revoke(ctx context.Context, sid string) {
	key := "mcpguard:revoked:" + sid
	_ = r.client.Set(ctx, key, "1", r.ttl).Err()
}

type RedisPins struct {
	client *redis.Client
}

func NewRedisPins(client *redis.Client) *RedisPins {
	return &RedisPins{client: client}
}

func (p *RedisPins) Get(key string) (string, bool) {
	val, err := p.client.HGet(context.Background(), "mcpguard:pins", key).Result()
	if err != nil {
		return "", false
	}
	return val, true
}

func (p *RedisPins) Set(key, digest string) {
	_ = p.client.HSet(context.Background(), "mcpguard:pins", key, digest).Err()
}

type RedisHITLStore struct {
	client *redis.Client
	ttl    time.Duration
}

func NewRedisHITLStore(client *redis.Client, ttl time.Duration) *RedisHITLStore {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &RedisHITLStore{client: client, ttl: ttl}
}

func (s *RedisHITLStore) Check(sessionID, agentID, subject, tool string, args map[string]any) (bool, *hitl.Request) {
	ctx := context.Background()
	fp := hitl.Fingerprint(sessionID, tool, args)
	fpKey := "mcpguard:hitl:fp:" + fp

	id, err := s.client.Get(ctx, fpKey).Result()
	if err == nil && id != "" {
		idKey := "mcpguard:hitl:id:" + id
		raw, err := s.client.Get(ctx, idKey).Bytes()
		if err == nil {
			var r hitl.Request
			if json.Unmarshal(raw, &r) == nil {
				switch r.Status {
				case hitl.Approved:
					r.Status = hitl.Used
					updated, _ := json.Marshal(r)
					pipe := s.client.Pipeline()
					pipe.Del(ctx, fpKey)
					pipe.Set(ctx, idKey, updated, s.ttl)
					_, _ = pipe.Exec(ctx)
					return true, &r
				case hitl.Pending, hitl.Denied:
					return false, &r
				}
			}
		}
	}

	b := make([]byte, 8)
	_, _ = rand.Read(b)
	reqID := "apr_" + hex.EncodeToString(b)

	r := &hitl.Request{
		ID:          reqID,
		SessionID:   sessionID,
		AgentID:     agentID,
		Subject:     subject,
		Tool:        tool,
		Arguments:   args,
		Fingerprint: fp,
		Status:      hitl.Pending,
		CreatedAt:   time.Now(),
	}
	data, _ := json.Marshal(r)
	pipe := s.client.Pipeline()
	pipe.Set(ctx, "mcpguard:hitl:id:"+reqID, data, s.ttl)
	pipe.Set(ctx, fpKey, reqID, s.ttl)
	_, _ = pipe.Exec(ctx)
	return false, r
}

func (s *RedisHITLStore) Decide(id string, approve bool) (*hitl.Request, bool) {
	ctx := context.Background()
	idKey := "mcpguard:hitl:id:" + id
	raw, err := s.client.Get(ctx, idKey).Bytes()
	if err != nil {
		return nil, false
	}
	var r hitl.Request
	if err := json.Unmarshal(raw, &r); err != nil || r.Status != hitl.Pending {
		return nil, false
	}
	if approve {
		r.Status = hitl.Approved
	} else {
		r.Status = hitl.Denied
	}
	updated, _ := json.Marshal(r)
	_ = s.client.Set(ctx, idKey, updated, s.ttl).Err()
	return &r, true
}

func (s *RedisHITLStore) List() []*hitl.Request {
	ctx := context.Background()
	keys, err := s.client.Keys(ctx, "mcpguard:hitl:id:*").Result()
	if err != nil {
		return nil
	}
	var out []*hitl.Request
	for _, k := range keys {
		raw, err := s.client.Get(ctx, k).Bytes()
		if err == nil {
			var r hitl.Request
			if json.Unmarshal(raw, &r) == nil && r.Status == hitl.Pending {
				out = append(out, &r)
			}
		}
	}
	return out
}
