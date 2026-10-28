// Package identity verifies the short-lived, scoped agent tokens that Sentinel
// Identity issues. In Phase 1 Shield ships an HS256 verifier so it runs
// standalone; Phase 2 swaps in ES256 + JWKS from Sentinel Identity without
// touching the gateway (it only depends on the Verifier interface).
package identity

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

var (
	ErrMissingToken = errors.New("missing bearer token")
	ErrBadToken     = errors.New("malformed or unverifiable token")
	ErrExpired      = errors.New("token expired")
	ErrRevoked      = errors.New("agent session revoked")
	ErrAudience     = errors.New("token audience/issuer mismatch")
)

// Principal is the verified identity of the agent making the request.
// Subject is the human (or service) on whose behalf the agent acts; AgentID
// is the agent itself (RFC 8693 "act" claim); SessionID scopes step counters,
// approvals and revocation.
type Principal struct {
	Subject   string
	AgentID   string
	SessionID string
	Scopes    []string
	ExpiresAt time.Time
}

// HasScope reports whether the principal holds the given scope.
func (p *Principal) HasScope(s string) bool {
	for _, have := range p.Scopes {
		if have == s {
			return true
		}
	}
	return false
}

// CallerKey identifies the caller for cache partitioning. It binds the human
// subject AND the agent session, so nothing cached for one caller can ever be
// served to another (mitigates MCP-2026-008 cross-caller cache poisoning).
func (p *Principal) CallerKey() string {
	return p.Subject + "|" + p.AgentID + "|" + p.SessionID
}

// Verifier turns a bearer token into a Principal.
type Verifier interface {
	Verify(ctx context.Context, bearer string) (*Principal, error)
}

// Revocations is the kill switch. Sentinel Identity will back this with Redis.
type Revocations interface {
	IsRevoked(ctx context.Context, sessionID string) bool
	Revoke(ctx context.Context, sessionID string)
}

// MemoryRevocations is an in-process revocation list for dev and tests.
type MemoryRevocations struct {
	mu sync.RWMutex
	m  map[string]time.Time
}

func NewMemoryRevocations() *MemoryRevocations { return &MemoryRevocations{m: map[string]time.Time{}} }

func (r *MemoryRevocations) IsRevoked(_ context.Context, sid string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.m[sid]
	return ok
}

func (r *MemoryRevocations) Revoke(_ context.Context, sid string) {
	r.mu.Lock()
	r.m[sid] = time.Now()
	r.mu.Unlock()
}

// HS256Verifier validates HMAC-SHA256 JWTs with standard + RFC 8693 claims.
type HS256Verifier struct {
	Secret      []byte
	Issuer      string
	Audience    string
	Revocations Revocations
	Now         func() time.Time
	Leeway      time.Duration
}

type claims struct {
	Iss   string          `json:"iss"`
	Sub   string          `json:"sub"`
	Aud   json.RawMessage `json:"aud"`
	Exp   int64           `json:"exp"`
	Nbf   int64           `json:"nbf"`
	Sid   string          `json:"sid"`
	Scope string          `json:"scope"`
	Act   *struct {
		Sub string `json:"sub"`
	} `json:"act"`
	AgentID string `json:"agent_id"`
}

func (v *HS256Verifier) Verify(ctx context.Context, bearer string) (*Principal, error) {
	if bearer == "" {
		return nil, ErrMissingToken
	}
	parts := strings.Split(bearer, ".")
	if len(parts) != 3 {
		return nil, ErrBadToken
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrBadToken
	}
	var hdr struct {
		Alg string `json:"alg"`
	}
	if json.Unmarshal(hdrRaw, &hdr) != nil || hdr.Alg != "HS256" { // reject alg=none / alg confusion
		return nil, ErrBadToken
	}
	mac := hmac.New(sha256.New, v.Secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, ErrBadToken
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrBadToken
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrBadToken
	}
	now := time.Now()
	if v.Now != nil {
		now = v.Now()
	}
	if c.Exp == 0 || now.After(time.Unix(c.Exp, 0).Add(v.Leeway)) {
		return nil, ErrExpired
	}
	if c.Nbf != 0 && now.Add(v.Leeway).Before(time.Unix(c.Nbf, 0)) {
		return nil, ErrBadToken
	}
	if v.Issuer != "" && c.Iss != v.Issuer {
		return nil, ErrAudience
	}
	if v.Audience != "" && !audContains(c.Aud, v.Audience) {
		return nil, ErrAudience
	}
	agent := c.AgentID
	if c.Act != nil && c.Act.Sub != "" {
		agent = c.Act.Sub
	}
	if agent == "" || c.Sid == "" {
		return nil, ErrBadToken // Shield requires an agent identity and a session
	}
	if v.Revocations != nil && v.Revocations.IsRevoked(ctx, c.Sid) {
		return nil, ErrRevoked
	}
	return &Principal{
		Subject:   c.Sub,
		AgentID:   agent,
		SessionID: c.Sid,
		Scopes:    strings.Fields(c.Scope),
		ExpiresAt: time.Unix(c.Exp, 0),
	}, nil
}

func audContains(raw json.RawMessage, want string) bool {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		return one == want
	}
	var many []string
	if json.Unmarshal(raw, &many) == nil {
		for _, a := range many {
			if a == want {
				return true
			}
		}
	}
	return false
}

// SignHS256 mints a token. Used by tests, the demo and the dev `mint` command;
// in production Sentinel Identity mints tokens via RFC 8693 token exchange.
func SignHS256(secret []byte, payload map[string]any) (string, error) {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	pb, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	p := base64.RawURLEncoding.EncodeToString(pb)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(h + "." + p))
	return h + "." + p + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}
