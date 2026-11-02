package hitl

import (
	"strings"
	"testing"
	"time"
)

func TestHITL_CheckCreatesPending(t *testing.T) {
	s := NewStore(10 * time.Minute)
	args := map[string]any{"customer_id": "123", "action": "refund"}

	allowed, req := s.Check("sess_1", "agent_1", "user_1", "payments/refund", args)
	if allowed {
		t.Fatal("expected allowed=false for unapproved tool call")
	}
	if req == nil {
		t.Fatal("expected non-nil Request")
	}
	if !strings.HasPrefix(req.ID, "apr_") {
		t.Errorf("expected ID prefix apr_, got %s", req.ID)
	}
	if req.Status != Pending {
		t.Errorf("expected status Pending, got %s", req.Status)
	}
	if req.Tool != "payments/refund" {
		t.Errorf("expected tool payments/refund, got %s", req.Tool)
	}

	// Immediate repeat should return the same pending request
	allowed2, req2 := s.Check("sess_1", "agent_1", "user_1", "payments/refund", args)
	if allowed2 {
		t.Fatal("expected allowed=false for still-pending tool call")
	}
	if req2.ID != req.ID {
		t.Errorf("expected same request ID %s, got %s", req.ID, req2.ID)
	}
}

func TestHITL_ApproveAndSingleUse(t *testing.T) {
	s := NewStore(10 * time.Minute)
	args := map[string]any{"query": "DROP TABLE users;"}

	_, req := s.Check("sess_1", "agent_1", "user_1", "db/query", args)

	// Admin approves
	updated, ok := s.Decide(req.ID, true)
	if !ok || updated.Status != Approved {
		t.Fatalf("expected Decide(true) to succeed, got ok=%v, status=%v", ok, updated.Status)
	}

	// Next call should be allowed once
	allowed, consumed := s.Check("sess_1", "agent_1", "user_1", "db/query", args)
	if !allowed {
		t.Fatal("expected allowed=true after approval")
	}
	if consumed.Status != Used {
		t.Errorf("expected status Used, got %s", consumed.Status)
	}

	// Next identical call should require a NEW approval
	allowedSecond, secondReq := s.Check("sess_1", "agent_1", "user_1", "db/query", args)
	if allowedSecond {
		t.Fatal("expected allowed=false on second attempt: approval must be single-use")
	}
	if secondReq.ID == req.ID {
		t.Errorf("expected new request ID for subsequent call, got same %s", secondReq.ID)
	}
	if secondReq.Status != Pending {
		t.Errorf("expected new request status Pending, got %s", secondReq.Status)
	}
}

func TestHITL_Deny(t *testing.T) {
	s := NewStore(10 * time.Minute)
	args := map[string]any{"target": "internal-server"}

	_, req := s.Check("sess_1", "agent_1", "user_1", "net/probe", args)

	updated, ok := s.Decide(req.ID, false)
	if !ok || updated.Status != Denied {
		t.Fatalf("expected Decide(false) to succeed with Denied status, got ok=%v, status=%v", ok, updated.Status)
	}

	allowed, reqAfter := s.Check("sess_1", "agent_1", "user_1", "net/probe", args)
	if allowed {
		t.Fatal("expected allowed=false after denial")
	}
	if reqAfter.Status != Denied {
		t.Errorf("expected status Denied, got %s", reqAfter.Status)
	}
}

func TestHITL_ArgumentTampering(t *testing.T) {
	s := NewStore(10 * time.Minute)
	originalArgs := map[string]any{"amount": float64(100), "to": "vendor_a"}
	tamperedArgs := map[string]any{"amount": float64(10000), "to": "attacker"}

	_, req := s.Check("sess_1", "agent_1", "user_1", "finance/transfer", originalArgs)

	// Admin approves the 100 transfer
	s.Decide(req.ID, true)

	// Agent tries to execute with tampered arguments
	allowed, tamperedReq := s.Check("sess_1", "agent_1", "user_1", "finance/transfer", tamperedArgs)
	if allowed {
		t.Fatal("SECURITY FAILURE: tampered arguments must not be permitted by previous approval!")
	}
	if tamperedReq.ID == req.ID {
		t.Fatal("tampered arguments must generate a different request")
	}
}

func TestHITL_ListPending(t *testing.T) {
	s := NewStore(10 * time.Minute)
	s.Check("s1", "a1", "u1", "tool1", map[string]any{"k": "v1"})
	_, r2 := s.Check("s2", "a2", "u2", "tool2", map[string]any{"k": "v2"})

	pending := s.List()
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending requests, got %d", len(pending))
	}

	// Decide one
	s.Decide(r2.ID, true)

	pendingAfter := s.List()
	if len(pendingAfter) != 1 {
		t.Fatalf("expected 1 pending request after approval, got %d", len(pendingAfter))
	}
}

func TestHITL_TTLExpiration(t *testing.T) {
	shortTTL := 20 * time.Millisecond
	s := NewStore(shortTTL)

	args := map[string]any{"cmd": "reboot"}
	_, req := s.Check("s1", "a1", "u1", "sys/reboot", args)
	s.Decide(req.ID, true)

	// Wait for TTL expiration
	time.Sleep(30 * time.Millisecond)

	allowed, newReq := s.Check("s1", "a1", "u1", "sys/reboot", args)
	if allowed {
		t.Fatal("expected allowed=false: expired approval must not be accepted")
	}
	if newReq.ID == req.ID {
		t.Errorf("expected new request after expiration, got old ID %s", newReq.ID)
	}
}
