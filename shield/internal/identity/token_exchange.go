// Package identity implements RFC 8693 OAuth 2.0 Token Exchange for agent identity delegation.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

// RFC 8693 token exchange and token type constants.
const (
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	TokenTypeJWT           = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeAccessToken   = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeIDToken       = "urn:ietf:params:oauth:token-type:id_token"
)

// Standard OAuth 2.0 error codes (RFC 6749 Section 5.2 & RFC 8693 Section 2.2.2).
const (
	OAuthErrInvalidRequest       = "invalid_request"
	OAuthErrInvalidClient        = "invalid_client"
	OAuthErrInvalidGrant         = "invalid_grant"
	OAuthErrUnauthorizedClient   = "unauthorized_client"
	OAuthErrUnsupportedGrantType = "unsupported_grant_type"
	OAuthErrInvalidScope         = "invalid_scope"
)

// OAuthError represents an RFC 6749 / RFC 8693 compliant error response.
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	StatusCode  int    `json:"-"`
}

func (e *OAuthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

// TokenExchangeRequest encapsulates the parameters of an RFC 8693 exchange request.
type TokenExchangeRequest struct {
	GrantType          string `json:"grant_type"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	ActorToken         string `json:"actor_token"`
	ActorTokenType     string `json:"actor_token_type"`
	Scope              string `json:"scope,omitempty"`
	Audience           string `json:"audience,omitempty"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
}

// TokenExchangeResponse encapsulates a successful RFC 8693 token exchange response.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope,omitempty"`
}

// TokenExchangeOptions configures the RFC 8693 token exchange engine.
type TokenExchangeOptions struct {
	// Issuer is the issuer identifier ("iss") for minted agent tokens.
	Issuer string

	// Audience is the default audience ("aud") for minted agent tokens.
	Audience string

	// SignerKey is the ECDSA private key used to sign minted ES256 JWTs.
	SignerKey *ecdsa.PrivateKey

	// SignerKeyID is the key ID ("kid") corresponding to the public key in the JWKS.
	SignerKeyID string

	// DefaultTTL is the default lifetime for minted tokens. Defaults to 10 minutes.
	DefaultTTL time.Duration

	// MaxTTL is the maximum permitted lifetime. Defaults to 15 minutes.
	MaxTTL time.Duration

	// SubjectTokenVerifier validates the human principal's subject_token.
	SubjectTokenVerifier Verifier

	// ActorTokenVerifier validates the agent's actor_token.
	ActorTokenVerifier Verifier

	// Registry is an optional agent identity store. When configured, agents must be
	// registered and active, and agent scopes are capped by the profile's AllowedScopes.
	Registry AgentRegistry

	// Now allows injecting a mock clock for testing. Defaults to time.Now.
	Now func() time.Time
}

// TokenExchangeEngine processes RFC 8693 token exchange requests and mints delegated tokens.
type TokenExchangeEngine struct {
	opts TokenExchangeOptions
}

// NewTokenExchangeEngine constructs a new RFC 8693 token exchange engine.
func NewTokenExchangeEngine(opts TokenExchangeOptions) (*TokenExchangeEngine, error) {
	if opts.SignerKey == nil {
		return nil, errors.New("signer key is required")
	}
	if opts.SubjectTokenVerifier == nil {
		return nil, errors.New("subject token verifier is required")
	}
	if opts.ActorTokenVerifier == nil {
		return nil, errors.New("actor token verifier is required")
	}
	if opts.DefaultTTL <= 0 {
		opts.DefaultTTL = 10 * time.Minute
	}
	if opts.MaxTTL <= 0 {
		opts.MaxTTL = 15 * time.Minute
	}
	if opts.DefaultTTL > opts.MaxTTL {
		opts.DefaultTTL = opts.MaxTTL
	}

	return &TokenExchangeEngine{opts: opts}, nil
}

// Exchange processes an RFC 8693 token exchange request.
func (e *TokenExchangeEngine) Exchange(ctx context.Context, req *TokenExchangeRequest) (*TokenExchangeResponse, error) {
	if req == nil {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidRequest,
			Description: "missing request body",
			StatusCode:  http.StatusBadRequest,
		}
	}

	// 1. Validate Grant Type
	if req.GrantType != GrantTypeTokenExchange {
		return nil, &OAuthError{
			Code:        OAuthErrUnsupportedGrantType,
			Description: fmt.Sprintf("unsupported grant_type: %s", req.GrantType),
			StatusCode:  http.StatusBadRequest,
		}
	}

	// 2. Validate subject_token and its type
	if req.SubjectToken == "" {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidRequest,
			Description: "subject_token is required",
			StatusCode:  http.StatusBadRequest,
		}
	}
	if !isSupportedTokenType(req.SubjectTokenType) {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidRequest,
			Description: fmt.Sprintf("unsupported subject_token_type: %s", req.SubjectTokenType),
			StatusCode:  http.StatusBadRequest,
		}
	}

	// 3. Validate actor_token and its type
	if req.ActorToken == "" {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidRequest,
			Description: "actor_token is required",
			StatusCode:  http.StatusBadRequest,
		}
	}
	if !isSupportedTokenType(req.ActorTokenType) {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidRequest,
			Description: fmt.Sprintf("unsupported actor_token_type: %s", req.ActorTokenType),
			StatusCode:  http.StatusBadRequest,
		}
	}

	// 4. Verify subject_token (Human identity & scopes)
	humanPrincipal, err := e.opts.SubjectTokenVerifier.Verify(ctx, req.SubjectToken)
	if err != nil {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidGrant,
			Description: fmt.Sprintf("invalid subject_token: %v", err),
			StatusCode:  http.StatusBadRequest,
		}
	}
	if humanPrincipal.Subject == "" {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidGrant,
			Description: "subject_token lacks a subject identifier",
			StatusCode:  http.StatusBadRequest,
		}
	}

	// 5. Verify actor_token (Agent identity & registered scopes)
	agentPrincipal, err := e.opts.ActorTokenVerifier.Verify(ctx, req.ActorToken)
	if err != nil {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidGrant,
			Description: fmt.Sprintf("invalid actor_token: %v", err),
			StatusCode:  http.StatusBadRequest,
		}
	}
	agentID := agentPrincipal.AgentID
	if agentID == "" {
		agentID = agentPrincipal.Subject
	}
	if agentID == "" {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidGrant,
			Description: "actor_token lacks an agent identifier",
			StatusCode:  http.StatusBadRequest,
		}
	}

	// 6. Agent Registry Validation (if configured)
	agentScopes := agentPrincipal.Scopes
	if e.opts.Registry != nil {
		profile, err := e.opts.Registry.Get(ctx, agentID)
		if err != nil {
			if errors.Is(err, ErrAgentNotFound) {
				return nil, &OAuthError{
					Code:        OAuthErrUnauthorizedClient,
					Description: fmt.Sprintf("agent %q is not registered", agentID),
					StatusCode:  http.StatusUnauthorized,
				}
			}
			return nil, fmt.Errorf("registry lookup failed: %w", err)
		}
		if profile.Status != AgentStatusActive {
			return nil, &OAuthError{
				Code:        OAuthErrUnauthorizedClient,
				Description: fmt.Sprintf("agent %q is %s", agentID, profile.Status),
				StatusCode:  http.StatusUnauthorized,
			}
		}
		agentScopes = capScopes(agentScopes, profile.AllowedScopes)
	}

	// 7. Scope Intersection Math: Granted = Human ∩ Agent ∩ Requested
	var requestedScopes []string
	if strings.TrimSpace(req.Scope) != "" {
		requestedScopes = strings.Fields(req.Scope)
	}

	grantedScopes, err := IntersectScopes(humanPrincipal.Scopes, agentScopes, requestedScopes)
	if err != nil {
		return nil, &OAuthError{
			Code:        OAuthErrInvalidScope,
			Description: err.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	}

	// 7. Determine Token Lifetime
	now := time.Now()
	if e.opts.Now != nil {
		now = e.opts.Now()
	}
	ttl := e.opts.DefaultTTL
	if ttl > e.opts.MaxTTL {
		ttl = e.opts.MaxTTL
	}

	// 8. Generate Cryptographically Secure Session ID (sid)
	sidBytes := make([]byte, 16)
	if _, err := rand.Read(sidBytes); err != nil {
		return nil, fmt.Errorf("failed to generate session id: %w", err)
	}
	sessionID := "sess_" + hex.EncodeToString(sidBytes)

	// 9. Audience Determination
	aud := req.Audience
	if aud == "" {
		aud = e.opts.Audience
	}

	// 10. Mint short-lived delegated ES256 JWT
	payload := map[string]any{
		"iss": e.opts.Issuer,
		"sub": humanPrincipal.Subject,
		"aud": aud,
		"exp": now.Add(ttl).Unix(),
		"nbf": now.Unix(),
		"iat": now.Unix(),
		"sid": sessionID,
		"act": map[string]any{
			"sub": agentID,
		},
		"scope": strings.Join(grantedScopes, " "),
	}

	tokenString, err := SignES256(e.opts.SignerKey, e.opts.SignerKeyID, payload)
	if err != nil {
		return nil, fmt.Errorf("failed to sign delegated token: %w", err)
	}

	return &TokenExchangeResponse{
		AccessToken:     tokenString,
		IssuedTokenType: TokenTypeAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       int64(ttl.Seconds()),
		Scope:           strings.Join(grantedScopes, " "),
	}, nil
}

// IntersectScopes calculates: Granted = Human ∩ Agent ∩ Requested.
// If requestedScopes is non-empty, every requested scope must exist in Human ∩ Agent.
// If requestedScopes is empty, all scopes in Human ∩ Agent are granted.
// If the intersection is empty, an error is returned.
func IntersectScopes(humanScopes, agentScopes, requestedScopes []string) ([]string, error) {
	humanSet := make(map[string]bool, len(humanScopes))
	for _, s := range humanScopes {
		humanSet[s] = true
	}

	baseAuthorized := make(map[string]bool)
	for _, s := range agentScopes {
		if humanSet[s] {
			baseAuthorized[s] = true
		}
	}

	if len(baseAuthorized) == 0 {
		return nil, errors.New("no overlapping authorized scopes between human principal and agent")
	}

	if len(requestedScopes) == 0 {
		var res []string
		for s := range baseAuthorized {
			res = append(res, s)
		}
		sort.Strings(res)
		return res, nil
	}

	var res []string
	for _, req := range requestedScopes {
		if !baseAuthorized[req] {
			return nil, fmt.Errorf("scope %q is not authorized by both human principal and agent", req)
		}
		res = append(res, req)
	}

	// Deduplicate and sort
	seen := make(map[string]bool, len(res))
	var unique []string
	for _, s := range res {
		if !seen[s] {
			seen[s] = true
			unique = append(unique, s)
		}
	}
	sort.Strings(unique)
	return unique, nil
}

func capScopes(agentScopes, allowedScopes []string) []string {
	if len(allowedScopes) == 0 {
		return agentScopes
	}
	for _, a := range allowedScopes {
		if a == "*" {
			return agentScopes
		}
	}
	allowedSet := make(map[string]bool, len(allowedScopes))
	for _, a := range allowedScopes {
		allowedSet[a] = true
	}
	var capped []string
	for _, s := range agentScopes {
		if allowedSet[s] {
			capped = append(capped, s)
		}
	}
	return capped
}

func isSupportedTokenType(t string) bool {
	switch t {
	case TokenTypeJWT, TokenTypeAccessToken, TokenTypeIDToken:
		return true
	default:
		return false
	}
}

// HTTPHandler returns an http.HandlerFunc handling POST /oauth/token.
func (e *TokenExchangeEngine) HTTPHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeOAuthError(w, &OAuthError{
				Code:        OAuthErrInvalidRequest,
				Description: "method must be POST",
				StatusCode:  http.StatusMethodNotAllowed,
			})
			return
		}

		var req TokenExchangeRequest
		contentType := r.Header.Get("Content-Type")
		if strings.HasPrefix(contentType, "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				writeOAuthError(w, &OAuthError{
					Code:        OAuthErrInvalidRequest,
					Description: "malformed JSON body",
					StatusCode:  http.StatusBadRequest,
				})
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				writeOAuthError(w, &OAuthError{
					Code:        OAuthErrInvalidRequest,
					Description: "malformed form body",
					StatusCode:  http.StatusBadRequest,
				})
				return
			}
			req.GrantType = r.FormValue("grant_type")
			req.SubjectToken = r.FormValue("subject_token")
			req.SubjectTokenType = r.FormValue("subject_token_type")
			req.ActorToken = r.FormValue("actor_token")
			req.ActorTokenType = r.FormValue("actor_token_type")
			req.Scope = r.FormValue("scope")
			req.Audience = r.FormValue("audience")
			req.RequestedTokenType = r.FormValue("requested_token_type")
		}

		resp, err := e.Exchange(r.Context(), &req)
		if err != nil {
			var oauthErr *OAuthError
			if errors.As(err, &oauthErr) {
				writeOAuthError(w, oauthErr)
				return
			}
			writeOAuthError(w, &OAuthError{
				Code:        "server_error",
				Description: err.Error(),
				StatusCode:  http.StatusInternalServerError,
			})
			return
		}

		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func writeOAuthError(w http.ResponseWriter, err *OAuthError) {
	status := err.StatusCode
	if status == 0 {
		status = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(err)
}
