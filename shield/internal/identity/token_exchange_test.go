package identity

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

func setupTestEngine(t *testing.T) (*TokenExchangeEngine, *ecdsa.PrivateKey, *ecdsa.PrivateKey) {
	t.Helper()

	signerPriv, _ := generateTestKey(t, "engine-key-1")
	humanVerifierKey, _ := generateTestKey(t, "human-key-1")
	humanPub, _ := jwk.Import(humanVerifierKey.Public())
	_ = humanPub.Set(jwk.KeyIDKey, "human-key-1")
	_ = humanPub.Set(jwk.AlgorithmKey, jwa.ES256())
	humanSet := jwk.NewSet()
	_ = humanSet.AddKey(humanPub)

	agentVerifierKey, _ := generateTestKey(t, "agent-key-1")
	agentPub, _ := jwk.Import(agentVerifierKey.Public())
	_ = agentPub.Set(jwk.KeyIDKey, "agent-key-1")
	_ = agentPub.Set(jwk.AlgorithmKey, jwa.ES256())
	agentSet := jwk.NewSet()
	_ = agentSet.AddKey(agentPub)

	humanVerifier := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: humanSet,
	})
	agentVerifier := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: agentSet,
	})

	engine, err := NewTokenExchangeEngine(TokenExchangeOptions{
		Issuer:               "https://identity.sentinel.local",
		Audience:             "mcpguard-shield",
		SignerKey:            signerPriv,
		SignerKeyID:          "engine-key-1",
		DefaultTTL:           10 * time.Minute,
		MaxTTL:               15 * time.Minute,
		SubjectTokenVerifier: humanVerifier,
		ActorTokenVerifier:   agentVerifier,
	})
	if err != nil {
		t.Fatalf("failed to create engine: %v", err)
	}

	return engine, humanVerifierKey, agentVerifierKey
}

func TestTokenExchange_Success(t *testing.T) {
	engine, humanKey, agentKey := setupTestEngine(t)
	now := time.Now()

	// 1. Mint human subject_token
	humanToken, err := SignES256(humanKey, "human-key-1", map[string]any{
		"sub":      "alice@example.com",
		"agent_id": "human-session",
		"sid":      "h-sess-1",
		"scope":    "db:read db:write crm:view",
		"exp":      now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 2. Mint agent actor_token
	agentToken, err := SignES256(agentKey, "agent-key-1", map[string]any{
		"sub":      "customer-support-bot",
		"agent_id": "customer-support-bot",
		"sid":      "a-sess-1",
		"scope":    "db:read crm:view metrics:write",
		"exp":      now.Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}

	// 3. Execute RFC 8693 Exchange
	req := &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     humanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       agentToken,
		ActorTokenType:   TokenTypeJWT,
		Scope:            "db:read crm:view",
	}

	resp, err := engine.Exchange(context.Background(), req)
	if err != nil {
		t.Fatalf("unexpected exchange error: %v", err)
	}

	if resp.TokenType != "Bearer" {
		t.Errorf("expected token_type Bearer, got %s", resp.TokenType)
	}
	if resp.IssuedTokenType != TokenTypeAccessToken {
		t.Errorf("expected issued_token_type %s, got %s", TokenTypeAccessToken, resp.IssuedTokenType)
	}
	if resp.ExpiresIn != 600 {
		t.Errorf("expected expires_in 600, got %d", resp.ExpiresIn)
	}
	if resp.Scope != "crm:view db:read" {
		t.Errorf("expected sorted scopes 'crm:view db:read', got %s", resp.Scope)
	}

	// 4. Verify minted token with JWKSVerifier
	enginePub, _ := jwk.Import(engine.opts.SignerKey.Public())
	_ = enginePub.Set(jwk.KeyIDKey, "engine-key-1")
	_ = enginePub.Set(jwk.AlgorithmKey, jwa.ES256())
	engineSet := jwk.NewSet()
	_ = engineSet.AddKey(enginePub)

	shieldVerifier := NewJWKSVerifier(JWKSVerifierOptions{
		StaticKeySet: engineSet,
		Issuer:       "https://identity.sentinel.local",
		Audience:     "mcpguard-shield",
	})

	principal, err := shieldVerifier.Verify(context.Background(), resp.AccessToken)
	if err != nil {
		t.Fatalf("shield verification failed for minted token: %v", err)
	}

	if principal.Subject != "alice@example.com" {
		t.Errorf("expected subject alice@example.com, got %s", principal.Subject)
	}
	if principal.AgentID != "customer-support-bot" {
		t.Errorf("expected agent customer-support-bot, got %s", principal.AgentID)
	}
	if !strings.HasPrefix(principal.SessionID, "sess_") {
		t.Errorf("expected session prefix 'sess_', got %s", principal.SessionID)
	}
	if !principal.HasScope("db:read") || !principal.HasScope("crm:view") || principal.HasScope("db:write") {
		t.Errorf("unexpected scopes in verified principal: %v", principal.Scopes)
	}
}

func TestTokenExchange_ScopeIntersectionLogic(t *testing.T) {
	// Case 1: Specific requested scope
	human := []string{"db:read", "db:write", "admin"}
	agent := []string{"db:read", "db:write", "metrics:write"}
	requested := []string{"db:read"}

	granted, err := IntersectScopes(human, agent, requested)
	if err != nil {
		t.Fatal(err)
	}
	if len(granted) != 1 || granted[0] != "db:read" {
		t.Errorf("expected [db:read], got %v", granted)
	}

	// Case 2: Omitted requested scope -> Human ∩ Agent
	grantedAll, err := IntersectScopes(human, agent, nil)
	if err != nil {
		t.Fatal(err)
	}
	expectedAll := "db:read db:write"
	if strings.Join(grantedAll, " ") != expectedAll {
		t.Errorf("expected %s, got %v", expectedAll, grantedAll)
	}

	// Case 3: Privilege Escalation Attempt (agent requests scope human lacks)
	humanLow := []string{"db:read"}
	agentHigh := []string{"db:read", "admin"}
	_, err = IntersectScopes(humanLow, agentHigh, []string{"admin"})
	if err == nil {
		t.Errorf("expected error when requesting unauthorized scope 'admin'")
	}

	// Case 4: Disjoint scopes (0 intersection)
	disjointHuman := []string{"hr:read"}
	disjointAgent := []string{"finance:read"}
	_, err = IntersectScopes(disjointHuman, disjointAgent, nil)
	if err == nil {
		t.Errorf("expected error when intersection is completely empty")
	}
}

func TestTokenExchange_ValidationErrors(t *testing.T) {
	engine, humanKey, agentKey := setupTestEngine(t)
	now := time.Now()

	validHumanToken, _ := SignES256(humanKey, "human-key-1", map[string]any{
		"sub": "alice", "agent_id": "h", "sid": "s1", "scope": "db:read", "exp": now.Add(time.Hour).Unix(),
	})
	validAgentToken, _ := SignES256(agentKey, "agent-key-1", map[string]any{
		"sub": "bot", "agent_id": "bot", "sid": "s2", "scope": "db:read", "exp": now.Add(time.Hour).Unix(),
	})

	// 1. Missing body
	if _, err := engine.Exchange(context.Background(), nil); err == nil {
		t.Errorf("expected error for nil request")
	}

	// 2. Unsupported grant type
	reqBadGrant := &TokenExchangeRequest{
		GrantType:        "authorization_code",
		SubjectToken:     validHumanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       validAgentToken,
		ActorTokenType:   TokenTypeJWT,
	}
	if _, err := engine.Exchange(context.Background(), reqBadGrant); err == nil || !strings.Contains(err.Error(), OAuthErrUnsupportedGrantType) {
		t.Errorf("expected unsupported_grant_type, got %v", err)
	}

	// 3. Missing subject_token
	reqNoSubject := &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       validAgentToken,
		ActorTokenType:   TokenTypeJWT,
	}
	if _, err := engine.Exchange(context.Background(), reqNoSubject); err == nil || !strings.Contains(err.Error(), OAuthErrInvalidRequest) {
		t.Errorf("expected invalid_request for missing subject_token, got %v", err)
	}

	// 4. Missing actor_token
	reqNoActor := &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     validHumanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorTokenType:   TokenTypeJWT,
	}
	if _, err := engine.Exchange(context.Background(), reqNoActor); err == nil || !strings.Contains(err.Error(), OAuthErrInvalidRequest) {
		t.Errorf("expected invalid_request for missing actor_token, got %v", err)
	}

	// 5. Expired human token
	expiredHuman, _ := SignES256(humanKey, "human-key-1", map[string]any{
		"sub": "alice", "agent_id": "h", "sid": "s1", "scope": "db:read", "exp": now.Add(-time.Hour).Unix(),
	})
	reqExpiredHuman := &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     expiredHuman,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       validAgentToken,
		ActorTokenType:   TokenTypeJWT,
	}
	if _, err := engine.Exchange(context.Background(), reqExpiredHuman); err == nil || !strings.Contains(err.Error(), OAuthErrInvalidGrant) {
		t.Errorf("expected invalid_grant for expired human token, got %v", err)
	}

	// 6. Expired agent token
	expiredAgent, _ := SignES256(agentKey, "agent-key-1", map[string]any{
		"sub": "bot", "agent_id": "bot", "sid": "s2", "scope": "db:read", "exp": now.Add(-time.Hour).Unix(),
	})
	reqExpiredAgent := &TokenExchangeRequest{
		GrantType:        GrantTypeTokenExchange,
		SubjectToken:     validHumanToken,
		SubjectTokenType: TokenTypeJWT,
		ActorToken:       expiredAgent,
		ActorTokenType:   TokenTypeJWT,
	}
	if _, err := engine.Exchange(context.Background(), reqExpiredAgent); err == nil || !strings.Contains(err.Error(), OAuthErrInvalidGrant) {
		t.Errorf("expected invalid_grant for expired agent token, got %v", err)
	}
}

func TestTokenExchange_HTTPHandler(t *testing.T) {
	engine, humanKey, agentKey := setupTestEngine(t)
	now := time.Now()

	validHumanToken, _ := SignES256(humanKey, "human-key-1", map[string]any{
		"sub": "alice@example.com", "agent_id": "h", "sid": "s1", "scope": "tools:read tools:write", "exp": now.Add(time.Hour).Unix(),
	})
	validAgentToken, _ := SignES256(agentKey, "agent-key-1", map[string]any{
		"sub": "coder-bot", "agent_id": "coder-bot", "sid": "s2", "scope": "tools:read", "exp": now.Add(time.Hour).Unix(),
	})

	handler := engine.HTTPHandler()

	// 1. GET is rejected
	reqGet := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	rrGet := httptest.NewRecorder()
	handler.ServeHTTP(rrGet, reqGet)
	if rrGet.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rrGet.Code)
	}

	// 2. Form POST succeeds
	form := url.Values{
		"grant_type":         {GrantTypeTokenExchange},
		"subject_token":      {validHumanToken},
		"subject_token_type": {TokenTypeJWT},
		"actor_token":        {validAgentToken},
		"actor_token_type":   {TokenTypeJWT},
		"scope":              {"tools:read"},
	}
	reqForm := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	reqForm.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrForm := httptest.NewRecorder()
	handler.ServeHTTP(rrForm, reqForm)

	if rrForm.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for form POST, got %d: %s", rrForm.Code, rrForm.Body.String())
	}
	var respForm TokenExchangeResponse
	if err := json.NewDecoder(rrForm.Body).Decode(&respForm); err != nil {
		t.Fatal(err)
	}
	if respForm.AccessToken == "" || respForm.Scope != "tools:read" {
		t.Errorf("unexpected response: %+v", respForm)
	}

	// 3. JSON POST succeeds
	bodyJSON, _ := json.Marshal(map[string]any{
		"grant_type":         GrantTypeTokenExchange,
		"subject_token":      validHumanToken,
		"subject_token_type": TokenTypeJWT,
		"actor_token":        validAgentToken,
		"actor_token_type":   TokenTypeJWT,
	})
	reqJSON := httptest.NewRequest(http.MethodPost, "/oauth/token", bytes.NewReader(bodyJSON))
	reqJSON.Header.Set("Content-Type", "application/json")
	rrJSON := httptest.NewRecorder()
	handler.ServeHTTP(rrJSON, reqJSON)

	if rrJSON.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for JSON POST, got %d: %s", rrJSON.Code, rrJSON.Body.String())
	}
	var respJSON TokenExchangeResponse
	if err := json.NewDecoder(rrJSON.Body).Decode(&respJSON); err != nil {
		t.Fatal(err)
	}
	if respJSON.AccessToken == "" || respJSON.Scope != "tools:read" {
		t.Errorf("unexpected response: %+v", respJSON)
	}

	// 4. Bad request returns OAuth error JSON
	formBad := url.Values{"grant_type": {"bad_grant"}}
	reqBad := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(formBad.Encode()))
	reqBad.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rrBad := httptest.NewRecorder()
	handler.ServeHTTP(rrBad, reqBad)

	if rrBad.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request, got %d", rrBad.Code)
	}
	var oauthErr OAuthError
	if err := json.NewDecoder(rrBad.Body).Decode(&oauthErr); err != nil {
		t.Fatal(err)
	}
	if oauthErr.Code != OAuthErrUnsupportedGrantType {
		t.Errorf("expected unsupported_grant_type, got %s", oauthErr.Code)
	}
}
