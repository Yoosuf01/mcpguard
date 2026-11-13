package state

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// DefaultRevocationChannel is the default Redis Pub/Sub topic for session revocations.
	DefaultRevocationChannel = "mcpguard:revocations:channel"
	// DefaultRevocationTTL is the default lifetime for revoked session entries.
	DefaultRevocationTTL = 7 * 24 * time.Hour
)

// RevocationMessage defines the JSON payload published over Redis Pub/Sub.
type RevocationMessage struct {
	SessionID string    `json:"session_id"`
	RevokedAt time.Time `json:"revoked_at"`
	Reason    string    `json:"reason,omitempty"`
}

// PubSubRevocationsOptions configures PubSubRedisRevocations.
type PubSubRevocationsOptions struct {
	Client  *redis.Client
	TTL     time.Duration
	Channel string
}

// PubSubRedisRevocations coordinates distributed real-time session revocations across
// multiple Shield replicas using Redis Pub/Sub and an in-memory fast-path lookup table.
type PubSubRedisRevocations struct {
	client  *redis.Client
	ttl     time.Duration
	channel string

	mu    sync.RWMutex
	local map[string]time.Time

	pubsub *redis.PubSub
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

var _ RevocationStore = (*PubSubRedisRevocations)(nil)

// NewPubSubRedisRevocations initializes the revocation store and starts the background
// Pub/Sub listener loop to receive instant revocation notices from other replicas.
func NewPubSubRedisRevocations(opts PubSubRevocationsOptions) (*PubSubRedisRevocations, error) {
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultRevocationTTL
	}
	channel := opts.Channel
	if channel == "" {
		channel = DefaultRevocationChannel
	}

	ctx, cancel := context.WithCancel(context.Background())
	pubsub := opts.Client.Subscribe(ctx, channel)

	// Confirm subscription is active to avoid race conditions.
	if _, err := pubsub.Receive(ctx); err != nil {
		cancel()
		_ = pubsub.Close()
		return nil, err
	}

	r := &PubSubRedisRevocations{
		client:  opts.Client,
		ttl:     ttl,
		channel: channel,
		local:   make(map[string]time.Time),
		pubsub:  pubsub,
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}

	go r.listen()

	return r, nil
}

// listen consumes messages from the Redis Pub/Sub subscription and updates the local cache.
func (r *PubSubRedisRevocations) listen() {
	defer close(r.done)
	ch := r.pubsub.Channel()
	for {
		select {
		case <-r.ctx.Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			if msg == nil {
				continue
			}
			r.handleMessage(msg.Payload)
		}
	}
}

// handleMessage unmarshals and stores a revocation into the local memory cache.
func (r *PubSubRedisRevocations) handleMessage(payload string) {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return
	}

	sid := payload
	revTime := time.Now()

	if strings.HasPrefix(payload, "{") {
		var msg RevocationMessage
		if err := json.Unmarshal([]byte(payload), &msg); err == nil && msg.SessionID != "" {
			sid = msg.SessionID
			if !msg.RevokedAt.IsZero() {
				revTime = msg.RevokedAt
			}
		}
	}

	r.mu.Lock()
	r.local[sid] = revTime
	r.mu.Unlock()
}

// IsRevoked checks if a session ID has been revoked.
// It checks the in-memory fast-path cache first (0 ms added latency). If absent,
// it queries Redis directly and populates the local cache if found.
func (r *PubSubRedisRevocations) IsRevoked(ctx context.Context, sid string) bool {
	if sid == "" {
		return false
	}

	// 1. Fast-path: local in-memory cache check
	r.mu.RLock()
	revTime, ok := r.local[sid]
	r.mu.RUnlock()

	if ok {
		if r.ttl <= 0 || time.Since(revTime) < r.ttl {
			return true
		}
		// Expired locally; remove stale entry
		r.mu.Lock()
		delete(r.local, sid)
		r.mu.Unlock()
	}

	// 2. Fallback: check Redis key (e.g. if this replica missed the pub/sub event or recently started)
	key := "mcpguard:revoked:" + sid
	val, err := r.client.Exists(ctx, key).Result()
	if err != nil {
		return false
	}
	if val > 0 {
		// Populate local fast-path
		r.mu.Lock()
		r.local[sid] = time.Now()
		r.mu.Unlock()
		return true
	}

	return false
}

// Revoke revokes a session ID: writes to persistent Redis key, updates local cache,
// and broadcasts to all other replicas over the Pub/Sub channel.
func (r *PubSubRedisRevocations) Revoke(ctx context.Context, sid string) {
	if sid == "" {
		return
	}

	now := time.Now()

	// 1. Immediately update local in-memory table
	r.mu.Lock()
	r.local[sid] = now
	r.mu.Unlock()

	// 2. Persist in Redis key with TTL
	key := "mcpguard:revoked:" + sid
	_ = r.client.Set(ctx, key, "1", r.ttl).Err()

	// 3. Publish to Pub/Sub channel for all peer replicas
	msg := RevocationMessage{
		SessionID: sid,
		RevokedAt: now,
	}
	data, err := json.Marshal(msg)
	if err == nil {
		_ = r.client.Publish(ctx, r.channel, string(data)).Err()
	} else {
		_ = r.client.Publish(ctx, r.channel, sid).Err()
	}
}

// Close gracefully terminates the Pub/Sub listener and closes the Redis connection.
func (r *PubSubRedisRevocations) Close() error {
	r.cancel()
	err := r.pubsub.Close()
	<-r.done
	return err
}

// LocalSize returns the count of items in the local cache (primarily for tests and telemetry).
func (r *PubSubRedisRevocations) LocalSize() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.local)
}
