// Package telemetry records one event per intercepted step. The default
// recorder writes structured JSON logs; swap in an OpenTelemetry recorder
// (one span per step) without changing the gateway.
package telemetry

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type Event struct {
	Time      time.Time
	Kind      string // "tools/call", "tools/list", "discovery", "auth", "cache"
	AgentID   string
	Subject   string
	SessionID string
	Backend   string
	Tool      string
	Decision  string // allow | deny | pending | flag | redact | error | dry_run_deny | dry_run_pending
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

// OTelRecorder records events as OpenTelemetry spans.
type OTelRecorder struct {
	Tracer trace.Tracer
}

func NewOTelRecorder(tracer trace.Tracer) *OTelRecorder {
	if tracer == nil {
		tracer = otel.GetTracerProvider().Tracer("github.com/Yoosuf01/mcpguard/shield")
	}
	return &OTelRecorder{Tracer: tracer}
}

func (r *OTelRecorder) Record(ctx context.Context, e Event) {
	if r.Tracer == nil {
		return
	}
	spanName := "mcp." + e.Kind
	startTime := e.Time
	if startTime.IsZero() {
		startTime = time.Now().Add(-e.Latency)
	}
	endTime := startTime.Add(e.Latency)

	_, span := r.Tracer.Start(ctx, spanName,
		trace.WithTimestamp(startTime),
		trace.WithAttributes(
			attribute.String("sentinel.agent_id", e.AgentID),
			attribute.String("sentinel.subject", e.Subject),
			attribute.String("sentinel.session_id", e.SessionID),
			attribute.String("sentinel.backend", e.Backend),
			attribute.String("sentinel.tool", e.Tool),
			attribute.String("sentinel.decision", e.Decision),
			attribute.String("sentinel.rule", e.Rule),
			attribute.String("sentinel.reason", e.Reason),
			attribute.Int64("sentinel.latency_ms", e.Latency.Milliseconds()),
			attribute.StringSlice("sentinel.findings", e.Findings),
		),
	)
	if e.Decision == "deny" || e.Decision == "error" {
		span.SetStatus(codes.Error, e.Reason)
	} else {
		span.SetStatus(codes.Ok, "")
	}
	span.End(trace.WithTimestamp(endTime))
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

// RingBuffer keeps the last N events in a thread-safe circular buffer for the admin console.
type RingBuffer struct {
	mu       sync.RWMutex
	events   []Event
	capacity int
}

func NewRingBuffer(capacity int) *RingBuffer {
	if capacity <= 0 {
		capacity = 250
	}
	return &RingBuffer{
		events:   make([]Event, 0, capacity),
		capacity: capacity,
	}
}

func (b *RingBuffer) Record(_ context.Context, e Event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	if len(b.events) >= b.capacity {
		b.events = b.events[1:]
	}
	b.events = append(b.events, e)
}

func (b *RingBuffer) Events() []Event {
	b.mu.RLock()
	defer b.mu.RUnlock()
	res := make([]Event, len(b.events))
	copy(res, b.events)
	return res
}
