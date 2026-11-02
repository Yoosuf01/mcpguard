package identity

import (
	"context"
	"testing"
	"time"
)

func TestVerify_ValidToken(t *testing.T) {
	secret := []byte("super-secret-key-32-bytes-long!!")
	now := time.Now()
	v := &HS256Verifier{
		Secret:   secret,
		Issuer:   "https://auth.mcpguard.io",
		Audience: "mcpguard-gateway",
		Now:      func() time.Time { return now },
	}

	claims := map[string]any{
		"iss":      "https://auth.mcpguard.io",
		"sub":      "user_123",
		"aud":      "mcpguard-gateway",
		"exp":      now.Add(10 * time.Minute).Unix(),
		"nbf":      now.Add(-1 * time.Minute).Unix(),
		"sid":      "sess_abc",
		"agent_id": "agent_forge",
		"scope":    "tools:read tools:execute",
	}

	tok, err := SignHS256(secret, claims)
	if err != nil {
		t.Fatalf("SignHS256 failed: %v", err)
	}

	p, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	if p.Subject != "user_123" {
		t.Errorf("expected subject user_123, got %s", p.Subject)
	}
	if p.AgentID != "agent_forge" {
		t.Errorf("expected agent agent_forge, got %s", p.AgentID)
	}
	if p.SessionID != "sess_abc" {
		t.Errorf("expected session sess_abc, got %s", p.SessionID)
	}
	if !p.HasScope("tools:read") || !p.HasScope("tools:execute") || p.HasScope("admin") {
		t.Errorf("unexpected scopes: %v", p.Scopes)
	}
	if p.CallerKey() != "user_123|agent_forge|sess_abc" {
		t.Errorf("unexpected CallerKey: %s", p.CallerKey())
	}
}

func TestVerify_MissingAndMalformedToken(t *testing.T) {
	v := &HS256Verifier{Secret: []byte("secret")}

	if _, err := v.Verify(context.Background(), ""); err != ErrMissingToken {
		t.Errorf("expected ErrMissingToken, got %v", err)
	}
	if _, err := v.Verify(context.Background(), "invalid.token"); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for 2 parts, got %v", err)
	}
	if _, err := v.Verify(context.Background(), "a.b.c.d"); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for 4 parts, got %v", err)
	}
	if _, err := v.Verify(context.Background(), "not-base64.not-base64.sig"); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for bad base64, got %v", err)
	}
}

func TestVerify_AlgNoneAndBadAlg(t *testing.T) {
	v := &HS256Verifier{Secret: []byte("secret")}

	// Test with alg none
	tok := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMifQ."
	if _, err := v.Verify(context.Background(), tok); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for alg=none, got %v", err)
	}

	// Test with alg RS256
	tokRS := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMifQ.c2ln"
	if _, err := v.Verify(context.Background(), tokRS); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for alg=RS256, got %v", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	tok, err := SignHS256([]byte("secret-A"), map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	v := &HS256Verifier{Secret: []byte("secret-B")}
	if _, err := v.Verify(context.Background(), tok); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for wrong secret, got %v", err)
	}
}

func TestVerify_ExpiredAndNbf(t *testing.T) {
	secret := []byte("secret")
	now := time.Now()

	v := &HS256Verifier{
		Secret: secret,
		Now:    func() time.Time { return now },
	}

	// Expired
	tokExpired, _ := SignHS256(secret, map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"exp":      now.Add(-10 * time.Second).Unix(),
	})
	if _, err := v.Verify(context.Background(), tokExpired); err != ErrExpired {
		t.Errorf("expected ErrExpired, got %v", err)
	}

	// Not before in future
	tokNbf, _ := SignHS256(secret, map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"exp":      now.Add(time.Hour).Unix(),
		"nbf":      now.Add(5 * time.Minute).Unix(),
	})
	if _, err := v.Verify(context.Background(), tokNbf); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for future nbf, got %v", err)
	}
}

func TestVerify_IssuerAndAudience(t *testing.T) {
	secret := []byte("secret")
	now := time.Now()
	v := &HS256Verifier{
		Secret:   secret,
		Issuer:   "auth.expected.com",
		Audience: "gateway-target",
		Now:      func() time.Time { return now },
	}

	// Wrong issuer
	tokBadIss, _ := SignHS256(secret, map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"iss":      "wrong.issuer.com",
		"aud":      "gateway-target",
		"exp":      now.Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(context.Background(), tokBadIss); err != ErrAudience {
		t.Errorf("expected ErrAudience for wrong iss, got %v", err)
	}

	// Wrong single audience
	tokBadAud, _ := SignHS256(secret, map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"iss":      "auth.expected.com",
		"aud":      "other-audience",
		"exp":      now.Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(context.Background(), tokBadAud); err != ErrAudience {
		t.Errorf("expected ErrAudience for wrong aud, got %v", err)
	}

	// Multi audience matching
	tokArrayAud, _ := SignHS256(secret, map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"iss":      "auth.expected.com",
		"aud":      []string{"service-x", "gateway-target", "service-y"},
		"exp":      now.Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(context.Background(), tokArrayAud); err != nil {
		t.Errorf("expected match for array aud containing gateway-target, got err %v", err)
	}
}

func TestVerify_ActClaimRFC8693(t *testing.T) {
	secret := []byte("secret")
	now := time.Now()
	v := &HS256Verifier{
		Secret: secret,
		Now:    func() time.Time { return now },
	}

	// Agent ID extracted from act.sub
	tok, _ := SignHS256(secret, map[string]any{
		"sub": "user_alice",
		"act": map[string]any{
			"sub": "delegated_agent_bob",
		},
		"sid": "sess_999",
		"exp": now.Add(time.Hour).Unix(),
	})
	p, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.AgentID != "delegated_agent_bob" {
		t.Errorf("expected AgentID delegated_agent_bob from act claim, got %s", p.AgentID)
	}
}

func TestVerify_Revocations(t *testing.T) {
	secret := []byte("secret")
	now := time.Now()
	revs := NewMemoryRevocations()
	v := &HS256Verifier{
		Secret:      secret,
		Revocations: revs,
		Now:         func() time.Time { return now },
	}

	tok, _ := SignHS256(secret, map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "kill-session-123",
		"exp":      now.Add(time.Hour).Unix(),
	})

	// Before revocation: passes
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected verify success before revocation, got %v", err)
	}

	// Revoke session
	revs.Revoke(context.Background(), "kill-session-123")
	if !revs.IsRevoked(context.Background(), "kill-session-123") {
		t.Fatal("expected IsRevoked to be true")
	}

	// After revocation: fails with ErrRevoked
	if _, err := v.Verify(context.Background(), tok); err != ErrRevoked {
		t.Errorf("expected ErrRevoked, got %v", err)
	}
}
