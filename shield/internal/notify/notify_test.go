package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
)

func TestSignAndVerifyLink_Success(t *testing.T) {
	n := NewNotifier(Config{
		HMACSecret:    "super-secret-signing-key-12345",
		PublicBaseURL: "http://localhost:8081",
		LinkTTL:       10 * time.Minute,
	})

	id := "apr_test123"
	exp := time.Now().Add(5 * time.Minute)
	link := n.SignLink(id, "approve", exp)

	if !strings.Contains(link, "action=approve") || !strings.Contains(link, "sig=") {
		t.Fatalf("unexpected link format: %s", link)
	}

	// Extract query params for verification
	parts := strings.Split(link, "?")
	if len(parts) != 2 {
		t.Fatalf("expected query string: %s", link)
	}
	var action, expStr, sig string
	for _, q := range strings.Split(parts[1], "&") {
		kv := strings.Split(q, "=")
		if len(kv) == 2 {
			switch kv[0] {
			case "action":
				action = kv[1]
			case "exp":
				expStr = kv[1]
			case "sig":
				sig = kv[1]
			}
		}
	}

	if err := n.VerifyLink(id, action, expStr, sig); err != nil {
		t.Fatalf("VerifyLink failed: %v", err)
	}
}

func TestVerifyLink_ExpiredAndTampered(t *testing.T) {
	n := NewNotifier(Config{
		HMACSecret: "secret-key",
	})

	id := "apr_abc"
	// Expired
	pastExp := time.Now().Add(-1 * time.Minute)
	linkExpired := n.SignLink(id, "approve", pastExp)
	expStr := strings.Split(strings.Split(linkExpired, "exp=")[1], "&")[0]
	sig := strings.Split(linkExpired, "sig=")[1]

	if err := n.VerifyLink(id, "approve", expStr, sig); err != ErrLinkExpired {
		t.Errorf("expected ErrLinkExpired, got %v", err)
	}

	// Tampered action (tried to swap "deny" to "approve" using the same sig)
	futureExp := time.Now().Add(10 * time.Minute)
	linkDeny := n.SignLink(id, "deny", futureExp)
	expStr2 := strings.Split(strings.Split(linkDeny, "exp=")[1], "&")[0]
	sig2 := strings.Split(linkDeny, "sig=")[1]

	if err := n.VerifyLink(id, "approve", expStr2, sig2); err != ErrInvalidSig {
		t.Errorf("expected ErrInvalidSig for tampered action, got %v", err)
	}
}

func TestNotify_WebhookDelivery(t *testing.T) {
	var received Payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("failed to decode webhook body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewNotifier(Config{
		WebhookURL:    server.URL,
		HMACSecret:    "webhook-key-456",
		PublicBaseURL: "http://mcpguard.internal:8081",
	})

	req := &hitl.Request{
		ID:        "apr_9999",
		AgentID:   "bot-1",
		Subject:   "alice",
		Tool:      "payments/charge",
		Arguments: map[string]any{"amount": 250},
	}

	if err := n.Notify(context.Background(), req); err != nil {
		t.Fatalf("Notify failed: %v", err)
	}

	if received.ApprovalID != "apr_9999" || received.Tool != "payments/charge" {
		t.Errorf("unexpected webhook payload: %+v", received)
	}
	if !strings.HasPrefix(received.ApproveURL, "http://mcpguard.internal:8081") {
		t.Errorf("unexpected approve URL: %s", received.ApproveURL)
	}
}
