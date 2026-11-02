// Package state provides abstract interfaces and pluggable backends (in-memory with TTL eviction
// and Redis for distributed multi-replica deployments) for Sentinel Shield runtime state:
// step counters, sliding-window rate limiters, token revocations, tool hash pins, and HITL approvals.
package state

import (
	"context"

	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
)

// CounterStore tracks per-session step totals and rate windows.
type CounterStore interface {
	Step(ctx context.Context, session string) (int, error)
	Rate(ctx context.Context, session string) (int, error)
	Reset(ctx context.Context, session string) error
}

// RevocationStore tracks revoked session IDs.
type RevocationStore interface {
	IsRevoked(ctx context.Context, sessionID string) bool
	Revoke(ctx context.Context, sessionID string)
}

// PinStore tracks approved digests for instructions and tools.
type PinStore interface {
	Get(key string) (string, bool)
	Set(key, digest string)
}

// HITLStore manages human approval lifecycles.
type HITLStore interface {
	Check(sessionID, agentID, subject, tool string, args map[string]any) (bool, *hitl.Request)
	Decide(id string, approve bool) (*hitl.Request, bool)
	List() []*hitl.Request
}
