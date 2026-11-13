package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func generateTestKey(t *testing.T, kid string) (*ecdsa.PrivateKey, jwk.Key) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ecdsa key: %v", err)
	}
	pubJWK, err := jwk.Import(priv.Public())
	if err != nil {
		t.Fatalf("failed to import public key: %v", err)
	}
	if kid != "" {
		_ = pubJWK.Set(jwk.KeyIDKey, kid)
	}
	_ = pubJWK.Set(jwk.AlgorithmKey, jwa.ES256())
	_ = pubJWK.Set(jwk.KeyUsageKey, "sig")
	return priv, pubJWK
}

func TestJWKSVerifier_ValidToken(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	now := time.Now().Truncate(time.Second)
	v := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: set,
		Issuer:       "https://auth.mcpguard.io",
		Audience:     "mcpguard-gateway",
		Now:          func() time.Time { return now },
		Leeway:       30 * time.Second,
	})

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

	tok, err := SignES256(priv, "key-1", claims)
	if err != nil {
		t.Fatalf("SignES256 failed: %v", err)
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
	if !p.ExpiresAt.Equal(now.Add(10 * time.Minute)) {
		t.Errorf("unexpected ExpiresAt: %v", p.ExpiresAt)
	}
}

func TestJWKSVerifier_RFC8693Delegation(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	now := time.Now()
	v := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: set,
		Now:          func() time.Time { return now },
	})

	claims := map[string]any{
		"sub": "human_alice",
		"act": map[string]any{
			"sub": "delegated_agent_bob",
		},
		"sid": "sess_999",
		"exp": now.Add(10 * time.Minute).Unix(),
	}

	tok, err := SignES256(priv, "key-1", claims)
	if err != nil {
		t.Fatalf("SignES256 failed: %v", err)
	}

	p, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if p.Subject != "human_alice" {
		t.Errorf("expected subject human_alice, got %s", p.Subject)
	}
	if p.AgentID != "delegated_agent_bob" {
		t.Errorf("expected AgentID delegated_agent_bob from act claim, got %s", p.AgentID)
	}
}

func TestJWKSVerifier_AlgorithmPinningAndConfusion(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	v := NewJWKSVerifier(JWKSVerifierOptions{StaticKeySet: set})

	// 1. alg: "none"
	tokNone := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjMiLCJzaWQiOiJzMSIsImFnZW50X2lkIjoiYTEiLCJleHAiOjQwMDAwMDAwMDB9."
	if _, err := v.Verify(context.Background(), tokNone); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for alg: none, got %v", err)
	}

	// 2. alg: "RS256"
	tokRS := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjMiLCJzaWQiOiJzMSIsImFnZW50X2lkIjoiYTEiLCJleHAiOjQwMDAwMDAwMDB9.c2ln"
	if _, err := v.Verify(context.Background(), tokRS); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for alg: RS256, got %v", err)
	}

	// 3. alg: "HS256" (Key confusion attack using raw public key bytes as HMAC secret)
	hsClaims := map[string]any{
		"sub":      "attacker",
		"sid":      "sess_hack",
		"agent_id": "malicious_bot",
		"exp":      time.Now().Add(time.Hour).Unix(),
	}
	fakeSecret := []byte("some-public-key-bytes-pretending-to-be-hmac")
	tokHS, err := SignHS256(fakeSecret, hsClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.Verify(context.Background(), tokHS); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for alg: HS256 key confusion attack, got %v", err)
	}

	// 4. Corrupted signature
	validTok, err := SignES256(priv, "key-1", hsClaims)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := validTok[:len(validTok)-5] + "XXXXX"
	if _, err := v.Verify(context.Background(), corrupted); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for corrupted signature, got %v", err)
	}
}

func TestJWKSVerifier_KeyRotationAndSingleflight(t *testing.T) {
	priv1, pub1 := generateTestKey(t, "key-1")
	priv2, pub2 := generateTestKey(t, "key-2")

	var mu sync.Mutex
	currentKeys := jwk.NewSet()
	_ = currentKeys.AddKey(pub1)

	var httpFetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&httpFetchCount, 1)
		mu.Lock()
		defer mu.Unlock()
		buf, _ := json.Marshal(currentKeys)
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf)
	}))
	defer server.Close()

	v := NewJWKSVerifier(JWKSVerifierOptions{
		JWKSURL:            server.URL,
		AllowInsecureHTTP:  true,
		AllowLoopback:      true,
		MinRefreshCooldown: 100 * time.Millisecond,
	})

	now := time.Now()
	claims := map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"exp":      now.Add(time.Hour).Unix(),
	}

	// First verify with key-1: fetches JWKS from server (fetch count = 1)
	tok1, _ := SignES256(priv1, "key-1", claims)
	p1, err := v.Verify(context.Background(), tok1)
	if err != nil {
		t.Fatalf("first verify failed: %v", err)
	}
	if p1.Subject != "u1" {
		t.Fatalf("unexpected principal: %+v", p1)
	}
	if count := atomic.LoadInt32(&httpFetchCount); count != 1 {
		t.Fatalf("expected 1 fetch, got %d", count)
	}

	// Subsequent verify with key-1: served from in-memory cache (fetch count remains 1)
	_, err = v.Verify(context.Background(), tok1)
	if err != nil {
		t.Fatalf("cached verify failed: %v", err)
	}
	if count := atomic.LoadInt32(&httpFetchCount); count != 1 {
		t.Fatalf("expected cached verify without fetch, got %d fetches", count)
	}

	// Key rotation happens on server: add key-2
	mu.Lock()
	_ = currentKeys.AddKey(pub2)
	mu.Unlock()

	// Wait past the cooldown so rotation can trigger refresh
	time.Sleep(150 * time.Millisecond)

	// Send 50 concurrent requests signed with new key-2:
	// Singleflight must ensure only 1 outbound HTTP fetch occurs!
	tok2, _ := SignES256(priv2, "key-2", claims)
	var wg sync.WaitGroup
	errCh := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, vErr := v.Verify(context.Background(), tok2)
			if vErr != nil {
				errCh <- vErr
			}
		}()
	}
	wg.Wait()
	close(errCh)

	for e := range errCh {
		t.Errorf("concurrent verify error: %v", e)
	}

	// Fetch count must have increased by exactly 1 (from 1 to 2)
	if count := atomic.LoadInt32(&httpFetchCount); count != 2 {
		t.Errorf("expected exactly 2 HTTP fetches after singleflight rotation, got %d", count)
	}
}

func TestJWKSVerifier_CooldownPreventsDos(t *testing.T) {
	_, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	var httpFetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&httpFetchCount, 1)
		buf, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf)
	}))
	defer server.Close()

	v := NewJWKSVerifier(JWKSVerifierOptions{
		JWKSURL:            server.URL,
		AllowInsecureHTTP:  true,
		AllowLoopback:      true,
		MinRefreshCooldown: 5 * time.Second,
	})

	// Generate a token signed with a random non-existent key
	privBogus, _ := generateTestKey(t, "bogus-key")
	tokBogus, _ := SignES256(privBogus, "bogus-key", map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})

	// First request: misses cache, executes fetch (fetch count = 1), fails because bogus-key doesn't exist
	if _, err := v.Verify(context.Background(), tokBogus); err != ErrBadToken {
		t.Errorf("expected ErrBadToken, got %v", err)
	}
	if count := atomic.LoadInt32(&httpFetchCount); count != 1 {
		t.Fatalf("expected 1 fetch, got %d", count)
	}

	// Rapid subsequent requests with different unknown kids within cooldown window:
	// Cooldown must kick in and NOT make HTTP calls!
	for i := 0; i < 10; i++ {
		privRand, _ := generateTestKey(t, fmt.Sprintf("random-%d", i))
		tokRand, _ := SignES256(privRand, fmt.Sprintf("random-%d", i), map[string]any{
			"sub":      "u1",
			"agent_id": "a1",
			"sid":      "s1",
			"exp":      time.Now().Add(time.Hour).Unix(),
		})
		if _, err := v.Verify(context.Background(), tokRand); err != ErrBadToken {
			t.Errorf("expected ErrBadToken, got %v", err)
		}
	}

	// Fetch count must still be 1!
	if count := atomic.LoadInt32(&httpFetchCount); count != 1 {
		t.Errorf("expected fetch count to remain 1 due to cooldown protection, got %d", count)
	}
}

func TestJWKSVerifier_SSRF(t *testing.T) {
	ctx := context.Background()

	// 1. Insecure scheme blocked when AllowInsecureHTTP is false
	v1 := NewJWKSVerifier(JWKSVerifierOptions{
		JWKSURL:           "http://example.com/jwks.json",
		AllowInsecureHTTP: false,
	})
	if err := v1.fetchJWKS(ctx); err == nil {
		t.Errorf("expected error for http:// scheme when AllowInsecureHTTP=false")
	}

	// 2. Loopback blocked when AllowLoopback is false
	v2 := NewJWKSVerifier(JWKSVerifierOptions{
		JWKSURL:           "http://127.0.0.1:8080/jwks.json",
		AllowInsecureHTTP: true,
		AllowLoopback:     false,
	})
	if err := v2.fetchJWKS(ctx); err == nil {
		t.Errorf("expected error for 127.0.0.1 when AllowLoopback=false")
	}

	// 3. Cloud metadata IP blocked
	v3 := NewJWKSVerifier(JWKSVerifierOptions{
		JWKSURL:           "http://169.254.169.254/latest/meta-data/jwks.json",
		AllowInsecureHTTP: true,
		AllowLoopback:     true,
	})
	if err := v3.fetchJWKS(ctx); err == nil {
		t.Errorf("expected error for 169.254.169.254")
	}

	// 4. Non-canonical IP encodings blocked
	nonCanonicalURLs := []string{
		"http://2130706433/jwks.json", // Decimal 127.0.0.1
		"http://0x7f000001/jwks.json", // Hex 127.0.0.1
		"http://0177.0.0.1/jwks.json", // Octal 127.0.0.1
		"http://127.1/jwks.json",      // Short 127.0.0.1
	}
	for _, rawURL := range nonCanonicalURLs {
		v := NewJWKSVerifier(JWKSVerifierOptions{
			JWKSURL:           rawURL,
			AllowInsecureHTTP: true,
			AllowLoopback:     false,
		})
		if err := v.fetchJWKS(ctx); err == nil {
			t.Errorf("expected SSRF block for non-canonical URL %s", rawURL)
		}
	}

	// 5. Internal hostnames blocked
	internalURLs := []string{
		"http://metadata.google.internal/computeMetadata/v1/jwks.json",
		"http://service.internal/jwks.json",
		"http://node.local/jwks.json",
		"http://localhost/jwks.json",
	}
	for _, rawURL := range internalURLs {
		v := NewJWKSVerifier(JWKSVerifierOptions{
			JWKSURL:           rawURL,
			AllowInsecureHTTP: true,
			AllowLoopback:     false,
		})
		if err := v.fetchJWKS(ctx); err == nil {
			t.Errorf("expected SSRF block for internal host URL %s", rawURL)
		}
	}

	// 6. HTTP Redirect to private IP is rejected by client
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/secret", http.StatusFound)
	}))
	defer redirectServer.Close()

	vRedirect := NewJWKSVerifier(JWKSVerifierOptions{
		JWKSURL:           redirectServer.URL,
		AllowInsecureHTTP: true,
		AllowLoopback:     true,
	})
	if err := vRedirect.fetchJWKS(ctx); err == nil {
		t.Errorf("expected error when JWKS endpoint redirects")
	}
}

func TestJWKSVerifier_ExpirationAndLeeway(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	now := time.Now()
	v := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: set,
		Now:          func() time.Time { return now },
		Leeway:       10 * time.Second,
	})

	claimsBase := map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
	}

	// 1. Expired beyond leeway
	cExp := map[string]any{"exp": now.Add(-20 * time.Second).Unix()}
	for k, val := range claimsBase {
		cExp[k] = val
	}
	tokExp, _ := SignES256(priv, "key-1", cExp)
	if _, err := v.Verify(context.Background(), tokExp); err != ErrExpired {
		t.Errorf("expected ErrExpired, got %v", err)
	}

	// 2. Expired within leeway: passes
	cLeeway := map[string]any{"exp": now.Add(-5 * time.Second).Unix()}
	for k, val := range claimsBase {
		cLeeway[k] = val
	}
	tokLeeway, _ := SignES256(priv, "key-1", cLeeway)
	if _, err := v.Verify(context.Background(), tokLeeway); err != nil {
		t.Errorf("expected verify success within leeway, got %v", err)
	}

	// 3. Not before in future
	cNbf := map[string]any{
		"exp": now.Add(time.Hour).Unix(),
		"nbf": now.Add(1 * time.Minute).Unix(),
	}
	for k, val := range claimsBase {
		cNbf[k] = val
	}
	tokNbf, _ := SignES256(priv, "key-1", cNbf)
	if _, err := v.Verify(context.Background(), tokNbf); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for future nbf, got %v", err)
	}
}

func TestJWKSVerifier_IssuerAndAudience(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	now := time.Now()
	v := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: set,
		Issuer:       "https://auth.expected.com",
		Audience:     "gateway-target",
		Now:          func() time.Time { return now },
	})

	claimsBase := map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"exp":      now.Add(time.Hour).Unix(),
	}

	// 1. Wrong issuer
	cBadIss := map[string]any{
		"iss": "https://wrong.issuer.com",
		"aud": "gateway-target",
	}
	for k, val := range claimsBase {
		cBadIss[k] = val
	}
	tokBadIss, _ := SignES256(priv, "key-1", cBadIss)
	if _, err := v.Verify(context.Background(), tokBadIss); err != ErrAudience {
		t.Errorf("expected ErrAudience for wrong iss, got %v", err)
	}

	// 2. Wrong single audience
	cBadAud := map[string]any{
		"iss": "https://auth.expected.com",
		"aud": "other-target",
	}
	for k, val := range claimsBase {
		cBadAud[k] = val
	}
	tokBadAud, _ := SignES256(priv, "key-1", cBadAud)
	if _, err := v.Verify(context.Background(), tokBadAud); err != ErrAudience {
		t.Errorf("expected ErrAudience for wrong aud, got %v", err)
	}

	// 3. Array audience containing target
	cArrayAud := map[string]any{
		"iss": "https://auth.expected.com",
		"aud": []string{"svc-1", "gateway-target", "svc-2"},
	}
	for k, val := range claimsBase {
		cArrayAud[k] = val
	}
	tokArrayAud, _ := SignES256(priv, "key-1", cArrayAud)
	if _, err := v.Verify(context.Background(), tokArrayAud); err != nil {
		t.Errorf("expected verify success for array audience, got %v", err)
	}
}

func TestJWKSVerifier_Revocations(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	revs := NewMemoryRevocations()
	now := time.Now()
	v := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: set,
		Revocations:  revs,
		Now:          func() time.Time { return now },
	})

	tok, _ := SignES256(priv, "key-1", map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "sess-to-kill",
		"exp":      now.Add(time.Hour).Unix(),
	})

	// Before revocation: succeeds
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("expected verify success before revocation, got %v", err)
	}

	// Revoke session
	revs.Revoke(context.Background(), "sess-to-kill")

	// After revocation: fails with ErrRevoked
	if _, err := v.Verify(context.Background(), tok); err != ErrRevoked {
		t.Errorf("expected ErrRevoked, got %v", err)
	}
}

func TestJWKSVerifier_MissingRequiredClaims(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	v := NewJWKSVerifier(JWKSVerifierOptions{StaticKeySet: set})

	// Empty token string
	if _, err := v.Verify(context.Background(), ""); err != ErrMissingToken {
		t.Errorf("expected ErrMissingToken, got %v", err)
	}

	// Missing sid
	tokNoSid, _ := SignES256(priv, "key-1", map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(context.Background(), tokNoSid); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for missing sid, got %v", err)
	}

	// Missing agent_id and act
	tokNoAgent, _ := SignES256(priv, "key-1", map[string]any{
		"sub": "u1",
		"sid": "s1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(context.Background(), tokNoAgent); err != ErrBadToken {
		t.Errorf("expected ErrBadToken for missing agent_id, got %v", err)
	}

	// Missing exp
	tokNoExp, _ := SignES256(priv, "key-1", map[string]any{
		"sub":      "u1",
		"sid":      "s1",
		"agent_id": "a1",
	})
	if _, err := v.Verify(context.Background(), tokNoExp); err != ErrExpired {
		t.Errorf("expected ErrExpired for missing exp, got %v", err)
	}
}

func TestJWKSVerifier_BackgroundRefreshAndClose(t *testing.T) {
	priv, pub := generateTestKey(t, "key-1")
	set := jwk.NewSet()
	_ = set.AddKey(pub)

	var httpFetchCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&httpFetchCount, 1)
		buf, _ := json.Marshal(set)
		w.Header().Set("Content-Type", "application/json")
		w.Write(buf)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	v := NewJWKSVerifier(JWKSVerifierOptions{
		JWKSURL:           server.URL,
		AllowInsecureHTTP: true,
		AllowLoopback:     true,
		RefreshInterval:   50 * time.Millisecond,
	})

	v.StartBackgroundRefresh(ctx)

	// Wait for background ticker to execute at least twice
	time.Sleep(120 * time.Millisecond)

	count := atomic.LoadInt32(&httpFetchCount)
	if count < 2 {
		t.Errorf("expected at least 2 background refreshes, got %d", count)
	}

	// Close terminates cleanly
	v.Close()

	// Calling Close multiple times is safe
	v.Close()

	tok, _ := SignES256(priv, "key-1", map[string]any{
		"sub":      "u1",
		"agent_id": "a1",
		"sid":      "s1",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	if _, err := v.Verify(context.Background(), tok); err != nil {
		t.Errorf("expected verify to succeed using cached keys after close, got %v", err)
	}
}
