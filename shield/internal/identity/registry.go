// Package identity provides agent identity registry and profile management for enterprise delegation.
package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// AgentStatus represents the lifecycle state of an agent identity.
type AgentStatus string

const (
	AgentStatusActive    AgentStatus = "active"
	AgentStatusSuspended AgentStatus = "suspended"
	AgentStatusRevoked   AgentStatus = "revoked"
)

// Common registry errors.
var (
	ErrAgentNotFound       = errors.New("agent not found")
	ErrAgentExists         = errors.New("agent already exists")
	ErrInvalidAgentProfile = errors.New("invalid agent profile")
	ErrAgentSuspended      = errors.New("agent is suspended")
	ErrAgentRevoked        = errors.New("agent is revoked")
)

// AgentProfile defines the registered enterprise identity and permissions of an AI agent.
type AgentProfile struct {
	ID              string      `json:"id"`
	Name            string      `json:"name"`
	Owner           string      `json:"owner"`
	AllowedScopes   []string    `json:"allowed_scopes"`
	AllowedBackends []string    `json:"allowed_backends"`
	Environment     string      `json:"environment"`
	Status          AgentStatus `json:"status"`
	CreatedAt       time.Time   `json:"created_at"`
	UpdatedAt       time.Time   `json:"updated_at"`
}

// Clone returns a deep copy of the agent profile.
func (p *AgentProfile) Clone() *AgentProfile {
	if p == nil {
		return nil
	}
	cp := *p
	if p.AllowedScopes != nil {
		cp.AllowedScopes = make([]string, len(p.AllowedScopes))
		copy(cp.AllowedScopes, p.AllowedScopes)
	}
	if p.AllowedBackends != nil {
		cp.AllowedBackends = make([]string, len(p.AllowedBackends))
		copy(cp.AllowedBackends, p.AllowedBackends)
	}
	return &cp
}

// AgentRegistry is the interface for registering, querying, and managing agent identities.
type AgentRegistry interface {
	Get(ctx context.Context, id string) (*AgentProfile, error)
	Register(ctx context.Context, profile *AgentProfile) error
	Update(ctx context.Context, profile *AgentProfile) error
	UpdateStatus(ctx context.Context, id string, status AgentStatus) error
	List(ctx context.Context) ([]*AgentProfile, error)
	Delete(ctx context.Context, id string) error
}

// MemoryAgentRegistry is an in-memory, thread-safe implementation of AgentRegistry.
type MemoryAgentRegistry struct {
	mu sync.RWMutex
	m  map[string]*AgentProfile
}

// NewMemoryAgentRegistry creates an empty in-memory agent registry.
func NewMemoryAgentRegistry() *MemoryAgentRegistry {
	return &MemoryAgentRegistry{
		m: make(map[string]*AgentProfile),
	}
}

func (r *MemoryAgentRegistry) Get(_ context.Context, id string) (*AgentProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	p, ok := r.m[id]
	if !ok {
		return nil, ErrAgentNotFound
	}
	return p.Clone(), nil
}

func (r *MemoryAgentRegistry) Register(_ context.Context, profile *AgentProfile) error {
	if profile == nil || profile.ID == "" {
		return ErrInvalidAgentProfile
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.m[profile.ID]; exists {
		return ErrAgentExists
	}

	now := time.Now()
	p := profile.Clone()
	if p.Status == "" {
		p.Status = AgentStatusActive
	}
	p.CreatedAt = now
	p.UpdatedAt = now
	r.m[p.ID] = p
	return nil
}

func (r *MemoryAgentRegistry) Update(_ context.Context, profile *AgentProfile) error {
	if profile == nil || profile.ID == "" {
		return ErrInvalidAgentProfile
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	existing, exists := r.m[profile.ID]
	if !exists {
		return ErrAgentNotFound
	}

	p := profile.Clone()
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now()
	r.m[p.ID] = p
	return nil
}

func (r *MemoryAgentRegistry) UpdateStatus(_ context.Context, id string, status AgentStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, exists := r.m[id]
	if !exists {
		return ErrAgentNotFound
	}

	p.Status = status
	p.UpdatedAt = time.Now()
	return nil
}

func (r *MemoryAgentRegistry) List(_ context.Context) ([]*AgentProfile, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	res := make([]*AgentProfile, 0, len(r.m))
	for _, p := range r.m {
		res = append(res, p.Clone())
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})
	return res, nil
}

func (r *MemoryAgentRegistry) Delete(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.m[id]; !exists {
		return ErrAgentNotFound
	}
	delete(r.m, id)
	return nil
}

// RedisAgentRegistry is a distributed Redis-backed implementation of AgentRegistry.
type RedisAgentRegistry struct {
	client *redis.Client
}

// NewRedisAgentRegistry creates a new Redis-backed agent registry.
func NewRedisAgentRegistry(client *redis.Client) *RedisAgentRegistry {
	return &RedisAgentRegistry{client: client}
}

func (r *RedisAgentRegistry) profileKey(id string) string {
	return "mcpguard:agent:profile:" + id
}

func (r *RedisAgentRegistry) setKey() string {
	return "mcpguard:agents:set"
}

func (r *RedisAgentRegistry) Get(ctx context.Context, id string) (*AgentProfile, error) {
	data, err := r.client.Get(ctx, r.profileKey(id)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrAgentNotFound
		}
		return nil, fmt.Errorf("failed to get agent profile: %w", err)
	}

	var p AgentProfile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal agent profile: %w", err)
	}
	return &p, nil
}

func (r *RedisAgentRegistry) Register(ctx context.Context, profile *AgentProfile) error {
	if profile == nil || profile.ID == "" {
		return ErrInvalidAgentProfile
	}

	p := profile.Clone()
	if p.Status == "" {
		p.Status = AgentStatusActive
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal agent profile: %w", err)
	}

	// SetNX to ensure atomicity
	key := r.profileKey(p.ID)
	ok, err := r.client.SetNX(ctx, key, data, 0).Result()
	if err != nil {
		return fmt.Errorf("failed to register agent in redis: %w", err)
	}
	if !ok {
		return ErrAgentExists
	}

	if err := r.client.SAdd(ctx, r.setKey(), p.ID).Err(); err != nil {
		return fmt.Errorf("failed to index agent in set: %w", err)
	}
	return nil
}

func (r *RedisAgentRegistry) Update(ctx context.Context, profile *AgentProfile) error {
	if profile == nil || profile.ID == "" {
		return ErrInvalidAgentProfile
	}

	existing, err := r.Get(ctx, profile.ID)
	if err != nil {
		return err
	}

	p := profile.Clone()
	p.CreatedAt = existing.CreatedAt
	p.UpdatedAt = time.Now()

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal agent profile: %w", err)
	}

	if err := r.client.Set(ctx, r.profileKey(p.ID), data, 0).Err(); err != nil {
		return fmt.Errorf("failed to update agent profile: %w", err)
	}
	return nil
}

func (r *RedisAgentRegistry) UpdateStatus(ctx context.Context, id string, status AgentStatus) error {
	p, err := r.Get(ctx, id)
	if err != nil {
		return err
	}

	p.Status = status
	p.UpdatedAt = time.Now()

	data, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("failed to marshal agent profile: %w", err)
	}

	if err := r.client.Set(ctx, r.profileKey(p.ID), data, 0).Err(); err != nil {
		return fmt.Errorf("failed to update agent status: %w", err)
	}
	return nil
}

func (r *RedisAgentRegistry) List(ctx context.Context) ([]*AgentProfile, error) {
	ids, err := r.client.SMembers(ctx, r.setKey()).Result()
	if err != nil {
		return nil, fmt.Errorf("failed to list agent ids: %w", err)
	}

	var res []*AgentProfile
	for _, id := range ids {
		p, err := r.Get(ctx, id)
		if err == nil {
			res = append(res, p)
		}
	}
	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})
	return res, nil
}

func (r *RedisAgentRegistry) Delete(ctx context.Context, id string) error {
	pipe := r.client.Pipeline()
	delCmd := pipe.Del(ctx, r.profileKey(id))
	pipe.SRem(ctx, r.setKey(), id)
	_, err := pipe.Exec(ctx)
	if err != nil {
		return fmt.Errorf("failed to delete agent: %w", err)
	}
	if delCmd.Val() == 0 {
		return ErrAgentNotFound
	}
	return nil
}
