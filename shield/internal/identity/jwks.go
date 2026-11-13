// Package identity verifies the short-lived, scoped agent tokens that Sentinel
// Identity issues. This file implements JWKSVerifier with ES256 support for Phase 2.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/sync/singleflight"

	"github.com/Yoosuf01/mcpguard/shield/internal/netutil"
)

var _ Verifier = (*JWKSVerifier)(nil)

// JWKSVerifierOptions configures the ES256 JWKS verifier.
type JWKSVerifierOptions struct {
	// JWKSURL is the remote endpoint serving JSON Web Key Sets (e.g. /.well-known/jwks.json).
	JWKSURL string

	// Issuer is the expected "iss" claim. If empty, issuer is not validated.
	Issuer string

	// Audience is the expected "aud" claim. If empty, audience is not validated.
	Audience string

	// Revocations provides the session kill switch check.
	Revocations Revocations

	// Now allows injecting a mock clock for testing. Defaults to time.Now.
	Now func() time.Time

	// Leeway provides clock skew tolerance for exp, nbf, and iat validation.
	Leeway time.Duration

	// RefreshInterval configures periodic background key refresh. If zero or negative,
	// background refresh is disabled and keys are fetched on demand.
	RefreshInterval time.Duration

	// MinRefreshCooldown limits how frequently the JWKS endpoint can be queried
	// when unknown "kid" values arrive, preventing DoS attacks. Defaults to 5s.
	MinRefreshCooldown time.Duration

	// AllowInsecureHTTP permits plain http:// endpoints (strictly for tests/dev).
	AllowInsecureHTTP bool

	// AllowLoopback permits loopback connections (127.0.0.1/::1) for httptest servers.
	AllowLoopback bool

	// HTTPClient overrides the default SSRF-safe HTTP client.
	HTTPClient *http.Client

	// StaticKeySet can preload keys without making network calls.
	StaticKeySet jwk.Set
}

// JWKSVerifier verifies ES256 tokens against an in-memory cached JWKS set with
// singleflight deduplication on key rotation and SSRF-safe remote fetching.
type JWKSVerifier struct {
	opts        JWKSVerifierOptions
	httpClient  *http.Client
	mu          sync.RWMutex
	cachedSet   jwk.Set
	lastFetch   time.Time
	sfGroup     singleflight.Group
	stopRefresh chan struct{}
}

// NewJWKSVerifier constructs a new ES256 JWKS verifier.
func NewJWKSVerifier(opts JWKSVerifierOptions) *JWKSVerifier {
	if opts.MinRefreshCooldown <= 0 {
		opts.MinRefreshCooldown = 5 * time.Second
	}

	client := opts.HTTPClient
	if client == nil {
		client = newSSRFSafeHTTPClient(opts.AllowLoopback, 10*time.Second)
	}

	var cached jwk.Set
	var lastFetch time.Time
	if opts.StaticKeySet != nil {
		cached = opts.StaticKeySet
		now := time.Now()
		if opts.Now != nil {
			now = opts.Now()
		}
		lastFetch = now
	}

	return &JWKSVerifier{
		opts:       opts,
		httpClient: client,
		cachedSet:  cached,
		lastFetch:  lastFetch,
	}
}

// StartBackgroundRefresh starts a background goroutine refreshing keys every RefreshInterval.
func (v *JWKSVerifier) StartBackgroundRefresh(ctx context.Context) {
	if v.opts.RefreshInterval <= 0 || v.opts.JWKSURL == "" {
		return
	}
	v.mu.Lock()
	if v.stopRefresh != nil {
		v.mu.Unlock()
		return
	}
	v.stopRefresh = make(chan struct{})
	stopCh := v.stopRefresh
	v.mu.Unlock()

	go func() {
		ticker := time.NewTicker(v.opts.RefreshInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-stopCh:
				return
			case <-ticker.C:
				_ = v.fetchJWKS(ctx)
			}
		}
	}()
}

// Close terminates any active background refresh routines.
func (v *JWKSVerifier) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.stopRefresh != nil {
		close(v.stopRefresh)
		v.stopRefresh = nil
	}
}

// Verify decodes and validates an ES256 JWT bearer token, returning a Principal.
func (v *JWKSVerifier) Verify(ctx context.Context, bearer string) (*Principal, error) {
	if bearer == "" {
		return nil, ErrMissingToken
	}

	// 1. Parse JWS structure and strictly enforce algorithm pinning (ES256 only).
	msg, err := jws.Parse([]byte(bearer))
	if err != nil {
		return nil, ErrBadToken
	}
	sigs := msg.Signatures()
	if len(sigs) != 1 {
		return nil, ErrBadToken
	}
	hdr := sigs[0].ProtectedHeaders()
	alg, ok := hdr.Algorithm()
	if !ok || alg.String() != "ES256" {
		// Strictly reject alg: none, HS256 (HMAC confusion), RS256, etc.
		return nil, ErrBadToken
	}
	kid, _ := hdr.KeyID()

	// 2. Resolve key from local cache or via singleflight remote refresh.
	key, err := v.resolveKey(ctx, kid)
	if err != nil || key == nil {
		return nil, ErrBadToken
	}

	// 3. Double-check resolved key parameters: must be EC P-256.
	if key.KeyType() != jwa.EC() {
		return nil, ErrBadToken
	}
	var rawKey any
	if err := jwk.Export(key, &rawKey); err != nil {
		return nil, ErrBadToken
	}
	ecPub, ok := rawKey.(*ecdsa.PublicKey)
	if !ok || ecPub.Curve != elliptic.P256() {
		return nil, ErrBadToken
	}

	// 4. Verify token signature and validate standard claims with jwt.Parse.
	now := time.Now()
	if v.opts.Now != nil {
		now = v.opts.Now()
	}
	parseOpts := []jwt.ParseOption{
		jwt.WithKey(jwa.ES256(), key),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(v.opts.Leeway),
		jwt.WithClock(jwt.ClockFunc(func() time.Time { return now })),
	}
	if v.opts.Issuer != "" {
		parseOpts = append(parseOpts, jwt.WithIssuer(v.opts.Issuer))
	}
	if v.opts.Audience != "" {
		parseOpts = append(parseOpts, jwt.WithAudience(v.opts.Audience))
	}

	tok, err := jwt.Parse([]byte(bearer), parseOpts...)
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			return nil, ErrExpired
		}
		if errors.Is(err, jwt.ValidateError()) {
			errStr := err.Error()
			if strings.Contains(errStr, `"iss" not satisfied`) || strings.Contains(errStr, `"aud" not satisfied`) {
				return nil, ErrAudience
			}
		}
		return nil, ErrBadToken
	}

	// 5. Enforce required expiration.
	exp, ok := tok.Expiration()
	if !ok || exp.IsZero() {
		return nil, ErrExpired
	}

	// 6. Extract Subject.
	sub, _ := tok.Subject()

	// 7. Extract Agent Identity: RFC 8693 "act.sub", fallback to "agent_id".
	var agentID string
	var actRaw any
	if tok.Get("act", &actRaw) == nil && actRaw != nil {
		if actMap, ok := actRaw.(map[string]any); ok {
			if s, ok := actMap["sub"].(string); ok {
				agentID = s
			}
		} else if bs, err := json.Marshal(actRaw); err == nil {
			var actStruct struct {
				Sub string `json:"sub"`
			}
			if json.Unmarshal(bs, &actStruct) == nil {
				agentID = actStruct.Sub
			}
		}
	}
	if agentID == "" {
		_ = tok.Get("agent_id", &agentID)
	}

	// 8. Extract Session ID (sid).
	var sid string
	_ = tok.Get("sid", &sid)

	if agentID == "" || sid == "" {
		return nil, ErrBadToken
	}

	// 9. Session Revocation check.
	if v.opts.Revocations != nil && v.opts.Revocations.IsRevoked(ctx, sid) {
		return nil, ErrRevoked
	}

	// 10. Extract Scopes.
	var scopeStr string
	_ = tok.Get("scope", &scopeStr)
	scopes := strings.Fields(scopeStr)

	return &Principal{
		Subject:   sub,
		AgentID:   agentID,
		SessionID: sid,
		Scopes:    scopes,
		ExpiresAt: exp,
	}, nil
}

// resolveKey looks up kid in the local cache, or executes a singleflight refresh if missing.
func (v *JWKSVerifier) resolveKey(ctx context.Context, kid string) (jwk.Key, error) {
	// Fast path: cached key hit
	if k := v.lookupKeyInCache(kid); k != nil {
		return k, nil
	}

	// If no remote URL is configured (static key set only), miss cannot be refreshed.
	if v.opts.JWKSURL == "" {
		return nil, errors.New("key not found in static key set")
	}

	// Check cooldown to avoid hammering the JWKS endpoint on repeated bogus kids.
	v.mu.RLock()
	last := v.lastFetch
	hasCached := v.cachedSet != nil
	v.mu.RUnlock()

	now := time.Now()
	if v.opts.Now != nil {
		now = v.opts.Now()
	}

	if hasCached && now.Sub(last) < v.opts.MinRefreshCooldown {
		return nil, errors.New("key not found; refresh in cooldown")
	}

	// Deduplicate concurrent refreshes using singleflight.
	_, err, _ := v.sfGroup.Do("jwks_refresh", func() (any, error) {
		return nil, v.fetchJWKS(ctx)
	})
	if err != nil {
		return nil, err
	}

	k := v.lookupKeyInCache(kid)
	if k == nil {
		return nil, errors.New("key not found in refreshed jwks")
	}
	return k, nil
}

// lookupKeyInCache looks up kid in the cached set. If kid is empty and exactly one key exists,
// that single key is returned.
func (v *JWKSVerifier) lookupKeyInCache(kid string) jwk.Key {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if v.cachedSet == nil {
		return nil
	}

	if kid != "" {
		if k, ok := v.cachedSet.LookupKeyID(kid); ok {
			return k
		}
		return nil
	}

	if v.cachedSet.Len() == 1 {
		k, _ := v.cachedSet.Key(0)
		return k
	}
	return nil
}

// fetchJWKS fetches the JWKS from JWKSURL using the SSRF-safe HTTP client.
func (v *JWKSVerifier) fetchJWKS(ctx context.Context) error {
	if v.opts.JWKSURL == "" {
		return errors.New("jwks url not configured")
	}

	u, err := url.Parse(v.opts.JWKSURL)
	if err != nil {
		return fmt.Errorf("invalid jwks url: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && (!v.opts.AllowInsecureHTTP || scheme != "http") {
		return fmt.Errorf("insecure or invalid url scheme: %s", scheme)
	}

	rawHost := u.Hostname()
	canonHost, isIP := netutil.NormalizeHost(rawHost)
	if isInternalHostname(canonHost) {
		return fmt.Errorf("ssrf blocked: internal hostname %s", canonHost)
	}
	if isIP {
		ip := net.ParseIP(canonHost)
		if isRestrictedIP(ip, v.opts.AllowLoopback) {
			return fmt.Errorf("ssrf blocked: prohibited IP %s", canonHost)
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.opts.JWKSURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "MCPGuard-Shield")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks endpoint returned status %d", resp.StatusCode)
	}

	limitedReader := io.LimitReader(resp.Body, 512*1024)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return fmt.Errorf("failed to read jwks response body: %w", err)
	}

	set, err := jwk.Parse(bodyBytes)
	if err != nil {
		return fmt.Errorf("failed to parse jwks response: %w", err)
	}

	now := time.Now()
	if v.opts.Now != nil {
		now = v.opts.Now()
	}

	v.mu.Lock()
	v.cachedSet = set
	v.lastFetch = now
	v.mu.Unlock()

	return nil
}

// newSSRFSafeHTTPClient creates an HTTP client with anti-DNS-rebinding dial checks
// and redirect blocking.
func newSSRFSafeHTTPClient(allowLoopback bool, timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("invalid address %q: %w", address, err)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("dial host %q is not an IP", host)
			}
			if isRestrictedIP(ip, allowLoopback) {
				return fmt.Errorf("ssrf blocked: connection to prohibited IP %s", ip)
			}
			return nil
		},
	}

	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   timeout,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return errors.New("redirects are not allowed for JWKS endpoints")
		},
	}
}

// isRestrictedIP returns true if the IP is private, link-local, loopback, or cloud metadata.
func isRestrictedIP(ip net.IP, allowLoopback bool) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		if v4.IsLoopback() {
			return !allowLoopback
		}
		if v4.IsPrivate() || v4.IsLinkLocalUnicast() || v4.IsLinkLocalMulticast() ||
			v4.IsUnspecified() || v4.IsInterfaceLocalMulticast() {
			return true
		}
		// Explicit cloud metadata IPs
		if v4.Equal(net.IPv4(169, 254, 169, 254)) || v4.Equal(net.IPv4(169, 254, 169, 253)) ||
			v4.Equal(net.IPv4(100, 100, 100, 200)) {
			return true
		}
		return false
	}

	// IPv6
	if ip.IsLoopback() {
		return !allowLoopback
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	return false
}

// isInternalHostname checks for localhost, metadata, and internal top-level domains.
func isInternalHostname(host string) bool {
	host = strings.Trim(strings.ToLower(host), "[]")
	if host == "localhost" || host == "metadata.google.internal" {
		return true
	}
	if strings.HasSuffix(host, ".internal") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".localhost") {
		return true
	}
	return false
}

// SignES256 mints an ES256 JWT using an ECDSA private key.
func SignES256(privKey *ecdsa.PrivateKey, kid string, payload map[string]any) (string, error) {
	if privKey == nil {
		return "", errors.New("nil private key")
	}

	builder := jwt.NewBuilder()
	for k, val := range payload {
		switch k {
		case "iss":
			if s, ok := val.(string); ok {
				builder.Issuer(s)
			}
		case "sub":
			if s, ok := val.(string); ok {
				builder.Subject(s)
			}
		case "aud":
			if s, ok := val.(string); ok {
				builder.Audience([]string{s})
			} else if arr, ok := val.([]string); ok {
				builder.Audience(arr)
			} else if arr, ok := val.([]any); ok {
				var auds []string
				for _, item := range arr {
					if s, ok := item.(string); ok {
						auds = append(auds, s)
					}
				}
				builder.Audience(auds)
			}
		case "exp":
			switch ts := val.(type) {
			case int64:
				builder.Expiration(time.Unix(ts, 0))
			case int:
				builder.Expiration(time.Unix(int64(ts), 0))
			case float64:
				builder.Expiration(time.Unix(int64(ts), 0))
			case time.Time:
				builder.Expiration(ts)
			}
		case "nbf":
			switch ts := val.(type) {
			case int64:
				builder.NotBefore(time.Unix(ts, 0))
			case int:
				builder.NotBefore(time.Unix(int64(ts), 0))
			case float64:
				builder.NotBefore(time.Unix(int64(ts), 0))
			case time.Time:
				builder.NotBefore(ts)
			}
		case "iat":
			switch ts := val.(type) {
			case int64:
				builder.IssuedAt(time.Unix(ts, 0))
			case int:
				builder.IssuedAt(time.Unix(int64(ts), 0))
			case float64:
				builder.IssuedAt(time.Unix(int64(ts), 0))
			case time.Time:
				builder.IssuedAt(ts)
			}
		default:
			builder.Claim(k, val)
		}
	}

	tok, err := builder.Build()
	if err != nil {
		return "", err
	}

	privJWK, err := jwk.Import(privKey)
	if err != nil {
		return "", err
	}
	if kid != "" {
		_ = privJWK.Set(jwk.KeyIDKey, kid)
	}
	_ = privJWK.Set(jwk.AlgorithmKey, jwa.ES256())
	_ = privJWK.Set(jwk.KeyUsageKey, "sig")

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), privJWK))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}
