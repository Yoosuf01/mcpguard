// Package gateway provides MCP proxying and runtime policy enforcement.
// This file implements RFC 9470 OAuth 2.0 Protected Resource Metadata.
package gateway

import (
	"encoding/json"
	"net/http"
)

// ProtectedResourceMetadata represents RFC 9470 OAuth 2.0 Protected Resource Metadata.
type ProtectedResourceMetadata struct {
	// Resource is the URL identifying the protected resource (e.g. "https://gateway.example.com/mcp").
	Resource string `json:"resource"`

	// AuthorizationServers lists the authorization servers capable of issuing access tokens for this resource.
	AuthorizationServers []string `json:"authorization_servers"`

	// ScopesSupported lists the OAuth scopes supported by this protected resource.
	ScopesSupported []string `json:"scopes_supported,omitempty"`

	// BearerMethodsSupported indicates token transmission mechanisms (e.g. ["header"]).
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`

	// ResourceSigningAlgValuesSupported lists supported signature algorithms (e.g. ["ES256"]).
	ResourceSigningAlgValuesSupported []string `json:"resource_signing_alg_values_supported,omitempty"`

	// ResourceDocumentation provides a link to human-readable API or gateway documentation.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// ProtectedResourceMetadataHandler returns an http.HandlerFunc that serves RFC 9470 metadata.
func (g *Gateway) ProtectedResourceMetadataHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		meta := g.opts.ResourceMetadata
		if meta == nil {
			// Provide intelligent defaults from gateway options and verifier settings
			meta = &ProtectedResourceMetadata{
				Resource:               "/mcp",
				AuthorizationServers:   []string{},
				BearerMethodsSupported: []string{"header"},
			}
		}

		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(meta)
	}
}
