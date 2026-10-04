package audit_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/audit"
)

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	w := audit.New(&buf)
	if err := w.Write(context.Background(), audit.Record{
		AgentID: "bot-1", Subject: "alice", Decision: "deny", Rule: "rate_limit",
	}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	var rec audit.Record
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if rec.Decision != "deny" {
		t.Errorf("decision mismatch: got %q", rec.Decision)
	}
}

func TestTimestampAutoSet(t *testing.T) {
	var buf bytes.Buffer
	_ = audit.New(&buf).Write(context.Background(), audit.Record{Decision: "allow"})
	var rec audit.Record
	_ = json.Unmarshal(buf.Bytes(), &rec)
	if rec.Timestamp.IsZero() {
		t.Fatal("Timestamp must be set automatically")
	}
}

func TestConcurrentSafe(t *testing.T) {
	var buf bytes.Buffer
	w := audit.New(&buf)
	done := make(chan struct{}, 50)
	for i := 0; i < 50; i++ {
		go func() {
			_ = w.Write(context.Background(), audit.Record{Decision: "allow"})
			done <- struct{}{}
		}()
	}
	for i := 0; i < 50; i++ { <-done }
	if n := len(strings.Split(strings.TrimSpace(buf.String()), "\n")); n != 50 {
		t.Fatalf("want 50 lines, got %d", n)
	}
}
