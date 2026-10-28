// Package telemetry records one event per intercepted step. The default
// recorder writes structured JSON logs; swap in an OpenTelemetry recorder
// (one span per step) without changing the gateway.
package telemetry

import (
	"context"
	"log/slog"
	"time"
)

type Event struct {
	Time      time.Time
	Kind      string // "tools/call", "tools/list", "discovery", "auth", "cache"
	AgentID   string
	Subject   string
	SessionID string
	Backend   string
	Tool      string
	Decision  string // allow | deny | pending | flag | redact | error
	Rule      string
	Reason    string
	Latency   time.Duration
	Findings  []string
}

type Recorder interface {
	Record(ctx context.Context, e Event)
}

type SlogRecorder struct{ L *slog.Logger }

func (r SlogRecorder) Record(ctx context.Context, e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	r.L.LogAttrs(ctx, slog.LevelInfo, "sentinel.step",
		slog.String("kind", e.Kind),
		slog.String("agent_id", e.AgentID),
		slog.String("subject", e.Subject),
		slog.String("session_id", e.SessionID),
		slog.String("backend", e.Backend),
		slog.String("tool", e.Tool),
		slog.String("decision", e.Decision),
		slog.String("rule", e.Rule),
		slog.String("reason", e.Reason),
		slog.Int64("latency_ms", e.Latency.Milliseconds()),
		slog.Any("findings", e.Findings),
	)
}

// Multi fans an event out to several recorders (e.g. logs + OTel + audit DB).
type Multi []Recorder

func (m Multi) Record(ctx context.Context, e Event) {
	for _, r := range m {
		r.Record(ctx, e)
	}
}

// Memory keeps events in memory; used by tests.
type Memory struct{ Events []Event }

func (m *Memory) Record(_ context.Context, e Event) { m.Events = append(m.Events, e) }
