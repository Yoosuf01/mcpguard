package identity

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestMemoryAgentRegistry_CRUD(t *testing.T) {
	ctx := context.Background()
	reg := NewMemoryAgentRegistry()

	// 1. Register invalid
	if err := reg.Register(ctx, nil); err != ErrInvalidAgentProfile {
		t.Errorf("expected ErrInvalidAgentProfile, got %v", err)
	}
	if err := reg.Register(ctx, &AgentProfile{ID: ""}); err != ErrInvalidAgentProfile {
		t.Errorf("expected ErrInvalidAgentProfile, got %v", err)
	}

	// 2. Register valid profile
	p1 := &AgentProfile{
		ID:              "agent-alpha",
		Name:            "Alpha Assistant",
		Owner:           "team-core@example.com",
		AllowedScopes:   []string{"tools:read", "tools:execute"},
		AllowedBackends: []string{"web", "postgres"},
		Environment:     "prod",
	}
	if err := reg.Register(ctx, p1); err != nil {
		t.Fatalf("failed to register agent: %v", err)
	}

	// 3. Register duplicate
	if err := reg.Register(ctx, p1); err != ErrAgentExists {
		t.Errorf("expected ErrAgentExists on duplicate register, got %v", err)
	}

	// 4. Get profile
	got, err := reg.Get(ctx, "agent-alpha")
	if err != nil {
		t.Fatalf("failed to get agent: %v", err)
	}
	if got.Name != "Alpha Assistant" || got.Status != AgentStatusActive {
		t.Errorf("unexpected profile: %+v", got)
	}
	if len(got.AllowedScopes) != 2 || got.AllowedScopes[0] != "tools:read" {
		t.Errorf("unexpected allowed scopes: %v", got.AllowedScopes)
	}

	// 5. Update profile
	got.Name = "Alpha Assistant v2"
	got.AllowedScopes = append(got.AllowedScopes, "admin:read")
	if err := reg.Update(ctx, got); err != nil {
		t.Fatalf("failed to update agent: %v", err)
	}
	updated, err := reg.Get(ctx, "agent-alpha")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Alpha Assistant v2" || len(updated.AllowedScopes) != 3 {
		t.Errorf("expected updated profile, got %+v", updated)
	}

	// 6. Update status
	if err := reg.UpdateStatus(ctx, "agent-alpha", AgentStatusSuspended); err != nil {
		t.Fatalf("failed to update status: %v", err)
	}
	suspended, _ := reg.Get(ctx, "agent-alpha")
	if suspended.Status != AgentStatusSuspended {
		t.Errorf("expected status suspended, got %s", suspended.Status)
	}

	// 7. List profiles
	_ = reg.Register(ctx, &AgentProfile{ID: "agent-beta", Name: "Beta"})
	list, err := reg.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "agent-alpha" || list[1].ID != "agent-beta" {
		t.Errorf("unexpected list: %+v", list)
	}

	// 8. Delete
	if err := reg.Delete(ctx, "agent-beta"); err != nil {
		t.Fatalf("failed to delete agent: %v", err)
	}
	if _, err := reg.Get(ctx, "agent-beta"); err != ErrAgentNotFound {
		t.Errorf("expected ErrAgentNotFound after delete, got %v", err)
	}
	if err := reg.Delete(ctx, "agent-beta"); err != ErrAgentNotFound {
		t.Errorf("expected ErrAgentNotFound on duplicate delete, got %v", err)
	}
}

func TestMemoryAgentRegistry_CloneIsolation(t *testing.T) {
	ctx := context.Background()
	reg := NewMemoryAgentRegistry()

	original := &AgentProfile{
		ID:            "agent-isolation",
		AllowedScopes: []string{"scope-1"},
	}
	_ = reg.Register(ctx, original)

	// Mutate original slice
	original.AllowedScopes[0] = "mutated"

	got, err := reg.Get(ctx, "agent-isolation")
	if err != nil {
		t.Fatal(err)
	}
	if got.AllowedScopes[0] != "scope-1" {
		t.Errorf("isolation failure: stored profile was mutated: %v", got.AllowedScopes)
	}

	// Mutate fetched slice
	got.AllowedScopes[0] = "mutated-again"
	got2, _ := reg.Get(ctx, "agent-isolation")
	if got2.AllowedScopes[0] != "scope-1" {
		t.Errorf("isolation failure: subsequent get was mutated: %v", got2.AllowedScopes)
	}
}

func TestRedisAgentRegistry_CRUD(t *testing.T) {
	ctx := context.Background()
	s := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: s.Addr()})
	defer client.Close()

	reg := NewRedisAgentRegistry(client)

	// 1. Register invalid
	if err := reg.Register(ctx, nil); err != ErrInvalidAgentProfile {
		t.Errorf("expected ErrInvalidAgentProfile, got %v", err)
	}
	if err := reg.Register(ctx, &AgentProfile{ID: ""}); err != ErrInvalidAgentProfile {
		t.Errorf("expected ErrInvalidAgentProfile, got %v", err)
	}

	// 2. Register valid profile
	p := &AgentProfile{
		ID:              "agent-redis-1",
		Name:            "Redis Agent",
		Owner:           "ops@example.com",
		AllowedScopes:   []string{"metrics:read", "logs:export"},
		AllowedBackends: []string{"datadog"},
		Environment:     "staging",
	}
	if err := reg.Register(ctx, p); err != nil {
		t.Fatalf("failed to register agent in redis: %v", err)
	}

	// 3. Register duplicate
	if err := reg.Register(ctx, p); err != ErrAgentExists {
		t.Errorf("expected ErrAgentExists in redis, got %v", err)
	}

	// 4. Get profile
	got, err := reg.Get(ctx, "agent-redis-1")
	if err != nil {
		t.Fatalf("failed to get agent from redis: %v", err)
	}
	if got.Name != "Redis Agent" || got.Status != AgentStatusActive {
		t.Errorf("unexpected profile from redis: %+v", got)
	}

	// 5. Update profile
	got.Name = "Redis Agent Updated"
	if err := reg.Update(ctx, got); err != nil {
		t.Fatalf("failed to update profile in redis: %v", err)
	}
	updated, _ := reg.Get(ctx, "agent-redis-1")
	if updated.Name != "Redis Agent Updated" {
		t.Errorf("expected updated name, got %s", updated.Name)
	}

	// 6. Update status
	if err := reg.UpdateStatus(ctx, "agent-redis-1", AgentStatusRevoked); err != nil {
		t.Fatalf("failed to update status in redis: %v", err)
	}
	revoked, _ := reg.Get(ctx, "agent-redis-1")
	if revoked.Status != AgentStatusRevoked {
		t.Errorf("expected status revoked, got %s", revoked.Status)
	}

	// 7. List profiles
	_ = reg.Register(ctx, &AgentProfile{ID: "agent-redis-2", Name: "Agent 2"})
	list, err := reg.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != "agent-redis-1" || list[1].ID != "agent-redis-2" {
		t.Errorf("unexpected redis list: %+v", list)
	}

	// 8. Delete
	if err := reg.Delete(ctx, "agent-redis-2"); err != nil {
		t.Fatalf("failed to delete agent in redis: %v", err)
	}
	if _, err := reg.Get(ctx, "agent-redis-2"); err != ErrAgentNotFound {
		t.Errorf("expected ErrAgentNotFound, got %v", err)
	}
	if err := reg.Delete(ctx, "agent-redis-2"); err != ErrAgentNotFound {
		t.Errorf("expected ErrAgentNotFound on duplicate delete, got %v", err)
	}
}

func TestTokenExchange_WithAgentRegistryIntegration(t *testing.T) {
	engine, humanKey, agentKey := setupTestEngine(t)
	reg := NewMemoryAgentRegistry()
	engine.opts.Registry = reg

	ctx := context.Background()
	now := time.Now()

	// 1. Pre-register active agent with restricted AllowedScopes: only "db:read"
	_ = reg.Register(ctx, &AgentProfile{
		ID:            "registered-agent",
		Name:          "Registered Agent",
		Status:        AgentStatusActive,
		AllowedScopes: []string{"db:read"}, // Note: does not allow db:write or admin
	})

	// Pre-register suspended agent
	_ = reg.Register(ctx, &AgentProfile{
		ID:            "suspended-agent",
		Name:          "Suspended Agent",
		Status:        AgentStatusSuspended,
		AllowedScopes: []string{"db:read"},
	})

	// Human token with broad scopes
	humanToken, _ := SignES256(humanKey, "human-key-1", map[string]any{
		"sub": "alice", "agent_id": "h", "sid": "s1", "scope": "db:read db:write admin", "exp": now.Add(time.Hour).Unix(),
	})

	// Case 1: Active registered agent requests allowed scope -> Success
	agentTokenActive, _ := SignES256(agentKey, "agent-key-1", map[string]any{
		"sub": "registered-agent", "agent_id": "registered-agent", "sid": "s2", "scope": "db:read db:write", "exp": now.Add(time.Hour).Unix(),
	})
	resp, err := engine.Exchange(ctx, &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     humanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       agentTokenActive,
		ActorTokenType:   TokenTypeJWT,
		Scope:            "db:read",
	})
	if err != nil {
		t.Fatalf("unexpected exchange error for active agent: %v", err)
	}
	if resp.Scope != "db:read" {
		t.Errorf("expected db:read scope, got %s", resp.Scope)
	}

	// Case 2: Scope capping: Agent credential claims db:write, but registry profile restricts to db:read!
	// When requesting db:write, exchange must fail with invalid_scope!
	_, err = engine.Exchange(ctx, &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     humanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       agentTokenActive,
		ActorTokenType:   TokenTypeJWT,
		Scope:            "db:write",
	})
	if err == nil || !strings.Contains(err.Error(), OAuthErrInvalidScope) {
		t.Errorf("expected invalid_scope when requesting scope exceeding registry cap, got %v", err)
	}

	// Case 3: Suspended agent is rejected with unauthorized_client
	agentTokenSuspended, _ := SignES256(agentKey, "agent-key-1", map[string]any{
		"sub": "suspended-agent", "agent_id": "suspended-agent", "sid": "s3", "scope": "db:read", "exp": now.Add(time.Hour).Unix(),
	})
	_, err = engine.Exchange(ctx, &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     humanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       agentTokenSuspended,
		ActorTokenType:   TokenTypeJWT,
	})
	if err == nil || !strings.Contains(err.Error(), OAuthErrUnauthorizedClient) {
		t.Errorf("expected unauthorized_client for suspended agent, got %v", err)
	}

	// Case 4: Unregistered agent is rejected with unauthorized_client
	agentTokenUnregistered, _ := SignES256(agentKey, "agent-key-1", map[string]any{
		"sub": "ghost-agent", "agent_id": "ghost-agent", "sid": "s4", "scope": "db:read", "exp": now.Add(time.Hour).Unix(),
	})
	_, err = engine.Exchange(ctx, &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     humanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       agentTokenUnregistered,
		ActorTokenType:   TokenTypeJWT,
	})
	if err == nil || !strings.Contains(err.Error(), OAuthErrUnauthorizedClient) {
		t.Errorf("expected unauthorized_client for unregistered agent, got %v", err)
	}
}

func TestMemoryAgentRegistry_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	reg := NewMemoryAgentRegistry()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		id := "agent-conc"
		go func(idx int) {
			defer wg.Done()
			if idx%3 == 0 {
				_ = reg.Register(ctx, &AgentProfile{ID: id, Name: "Initial"})
			} else if idx%3 == 1 {
				_ = reg.UpdateStatus(ctx, id, AgentStatusActive)
			} else {
				_, _ = reg.Get(ctx, id)
			}
		}(i)
	}
	wg.Wait()
}
