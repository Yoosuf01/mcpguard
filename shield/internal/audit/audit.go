// Package audit writes immutable append-only audit records as JSON lines.
// Every policy decision is captured: timestamp, request_id, agent, tool,
// decision, rule, reason, latency.
package audit

import (
	"context"
	"encoding/json"
	"io"
	"sync"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/requestid"
)

// Record is a single immutable audit event.
type Record struct {
	Timestamp time.Time `json:"ts"`
	RequestID string    `json:"request_id,omitempty"`
	AgentID   string    `json:"agent_id"`
	Subject   string    `json:"subject"`
	SessionID string    `json:"session_id"`
	Backend   string    `json:"backend,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	Decision  string    `json:"decision"`
	Rule      string    `json:"rule"`
	Reason    string    `json:"reason,omitempty"`
	LatencyMs int64     `json:"latency_ms,omitempty"`
	Findings  []string  `json:"findings,omitempty"`
}

// Writer serialises audit records as JSON lines. Safe for concurrent use.
type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

// New returns a Writer that emits to w.
func New(w io.Writer) *Writer {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return &Writer{enc: enc}
}

// Write records r. The timestamp and request ID are set automatically.
func (aw *Writer) Write(ctx context.Context, r Record) error {
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	r.RequestID = requestid.FromContext(ctx)
	aw.mu.Lock()
	defer aw.mu.Unlock()
	return aw.enc.Encode(r)
}
