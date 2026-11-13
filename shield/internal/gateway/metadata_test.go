package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/guard"
	"github.com/Yoosuf01/mcpguard/shield/internal/identity"
	"github.com/Yoosuf01/mcpguard/shield/internal/policy"
	"github.com/Yoosuf01/mcpguard/shield/internal/telemetry"
)

func newTestMetadataGateway(opts Options) *Gateway {
	pol, _ := policy.Parse([]byte("version: \"1\"\n"))
	return New(opts, policy.NewEngine(pol, nil), &identity.HS256Verifier{Secret: []byte("secret")}, &telemetry.Memory{}, guard.NewMemoryPins())
}

func TestProtectedResourceMetadataHandler_Success(t *testing.T) {
	meta := &ProtectedResourceMetadata{
		Resource:                          "https://gateway.mcpguard.io/mcp",
		AuthorizationServers:              []string{"https://identity.sentinel.local"},
		ScopesSupported:                   []string{"db:read", "db:write", "crm:view"},
		BearerMethodsSupported:            []string{"header"},
		ResourceSigningAlgValuesSupported: []string{"ES256"},
		ResourceDocumentation:             "https://docs.mcpguard.io",
	}

	gw := newTestMetadataGateway(Options{
		ResourceMetadata: meta,
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	gw.ProtectedResourceMetadataHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	ct := rr.Header().Get("Content-Type")
	if ct != "application/json; charset=UTF-8" {
		t.Errorf("unexpected Content-Type: %s", ct)
	}
	cc := rr.Header().Get("Cache-Control")
	if cc != "public, max-age=3600" {
		t.Errorf("unexpected Cache-Control: %s", cc)
	}

	var parsed ProtectedResourceMetadata
	if err := json.NewDecoder(rr.Body).Decode(&parsed); err != nil {
		t.Fatalf("failed to decode metadata json: %v", err)
	}

	if parsed.Resource != "https://gateway.mcpguard.io/mcp" {
		t.Errorf("expected resource %s, got %s", meta.Resource, parsed.Resource)
	}
	if len(parsed.AuthorizationServers) != 1 || parsed.AuthorizationServers[0] != "https://identity.sentinel.local" {
		t.Errorf("unexpected authorization_servers: %v", parsed.AuthorizationServers)
	}
	if len(parsed.ScopesSupported) != 3 || parsed.ScopesSupported[0] != "db:read" {
		t.Errorf("unexpected scopes_supported: %v", parsed.ScopesSupported)
	}
	if len(parsed.BearerMethodsSupported) != 1 || parsed.BearerMethodsSupported[0] != "header" {
		t.Errorf("unexpected bearer_methods_supported: %v", parsed.BearerMethodsSupported)
	}
}

func TestProtectedResourceMetadataHandler_MethodNotAllowed(t *testing.T) {
	gw := newTestMetadataGateway(Options{})

	req := httptest.NewRequest(http.MethodPost, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	gw.ProtectedResourceMetadataHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 Method Not Allowed, got %d", rr.Code)
	}
	if rr.Header().Get("Allow") != "GET" {
		t.Errorf("expected Allow: GET, got %s", rr.Header().Get("Allow"))
	}
}

func TestProtectedResourceMetadataHandler_Defaults(t *testing.T) {
	gw := newTestMetadataGateway(Options{
		ResourceMetadata: nil, // Trigger defaults
	})

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	gw.ProtectedResourceMetadataHandler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}

	var parsed ProtectedResourceMetadata
	if err := json.NewDecoder(rr.Body).Decode(&parsed); err != nil {
		t.Fatalf("failed to decode json: %v", err)
	}

	if parsed.Resource != "/mcp" {
		t.Errorf("expected default resource '/mcp', got %s", parsed.Resource)
	}
	if len(parsed.BearerMethodsSupported) != 1 || parsed.BearerMethodsSupported[0] != "header" {
		t.Errorf("expected default bearer_methods_supported ['header'], got %v", parsed.BearerMethodsSupported)
	}
}

func TestProtectedResourceMetadata_ServeHTTPRouting(t *testing.T) {
	meta := &ProtectedResourceMetadata{
		Resource:             "http://localhost:8080/mcp",
		AuthorizationServers: []string{"https://auth.example.com"},
	}
	gw := newTestMetadataGateway(Options{
		ResourceMetadata: meta,
	})

	// Test GET to ServeHTTP on metadata path
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	rr := httptest.NewRecorder()

	gw.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected ServeHTTP to handle /.well-known/oauth-protected-resource with 200, got %d", rr.Code)
	}

	var parsed ProtectedResourceMetadata
	if err := json.NewDecoder(rr.Body).Decode(&parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Resource != "http://localhost:8080/mcp" {
		t.Errorf("expected resource http://localhost:8080/mcp, got %s", parsed.Resource)
	}
}
