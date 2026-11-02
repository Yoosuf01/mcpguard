package telemetry

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace/noop"
)

func TestMemoryRecorder(t *testing.T) {
	mem := &Memory{}
	ev := Event{
		Kind:     "tools/call",
		AgentID:  "agent-1",
		Tool:     "calc",
		Decision: "allow",
		Latency:  10 * time.Millisecond,
	}
	mem.Record(context.Background(), ev)

	if len(mem.Events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(mem.Events))
	}
	if mem.Events[0].AgentID != "agent-1" {
		t.Errorf("expected agent-1, got %s", mem.Events[0].AgentID)
	}
}

func TestMultiRecorder(t *testing.T) {
	mem1 := &Memory{}
	mem2 := &Memory{}
	multi := Multi{mem1, mem2}

	ev := Event{Kind: "auth", Decision: "deny", Reason: "bad token"}
	multi.Record(context.Background(), ev)

	if len(mem1.Events) != 1 || len(mem2.Events) != 1 {
		t.Fatalf("expected both recorders to receive event")
	}
	if mem1.Events[0].Reason != "bad token" || mem2.Events[0].Reason != "bad token" {
		t.Errorf("mismatched event data in multi recorder")
	}
}

func TestSlogRecorder(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	rec := SlogRecorder{L: logger}

	ev := Event{
		Kind:     "discovery",
		Backend:  "weather",
		Decision: "allow",
		Rule:     "discovery_guard",
		Findings: []string{"clean"},
	}
	rec.Record(context.Background(), ev)

	out := buf.String()
	if !strings.Contains(out, `"kind":"discovery"`) || !strings.Contains(out, `"backend":"weather"`) {
		t.Errorf("expected structured JSON log with event attributes, got: %s", out)
	}
}

func TestOTelRecorder(t *testing.T) {
	tp := noop.NewTracerProvider()
	rec := NewOTelRecorder(tp.Tracer("test"))

	ev := Event{
		Kind:     "tools/call",
		AgentID:  "agent-otel",
		Backend:  "postgres",
		Tool:     "query",
		Decision: "deny",
		Rule:     "deny_arg_pattern",
		Reason:   "drop table",
		Latency:  5 * time.Millisecond,
		Findings: []string{"sql_injection"},
	}

	rec.Record(context.Background(), ev)
}
