// Package config loads, expands environment variables in, and validates
// the MCPGuard gateway configuration. All validation errors are returned
// together so operators fix everything in one restart cycle.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Gateway is the root configuration structure.
type Gateway struct {
	Listen      string    `yaml:"listen"`
	AdminListen string    `yaml:"admin_listen"`
	AdminToken  string    `yaml:"admin_token"`
	PolicyFile  string    `yaml:"policy_file"`
	Strict      bool      `yaml:"strict_headers"`
	Separator   string    `yaml:"tool_separator"`
	Auth        Auth      `yaml:"auth"`
	Backends    []Backend `yaml:"backends"`
	Logging     Logging   `yaml:"logging"`
	HITL        HITL      `yaml:"hitl"`
}

// Auth holds JWT verification parameters.
type Auth struct {
	HS256Secret     string        `yaml:"hs256_secret"`
	JWKSURL         string        `yaml:"jwks_url"`
	Issuer          string        `yaml:"issuer"`
	Audience        string        `yaml:"audience"`
	Leeway          time.Duration `yaml:"leeway"`
	ResourceURL     string        `yaml:"resource_url"`
	AuthServers     []string      `yaml:"authorization_servers"`
	ScopesSupported []string      `yaml:"scopes_supported"`
}

// Backend is a single upstream MCP server.
type Backend struct {
	Name    string        `yaml:"name"`
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
}

// Logging controls structured log output format and verbosity.
type Logging struct {
	Format string `yaml:"format"` // "json" | "text"
	Level  string `yaml:"level"`  // "debug" | "info" | "warn" | "error"
}

// HITL controls human-in-the-loop approval behaviour.
type HITL struct {
	ApprovalTTL    time.Duration `yaml:"approval_ttl"`
	WebhookURL     string        `yaml:"webhook_url"`
	WebhookSecret  string        `yaml:"webhook_secret"`
	WebhookTimeout time.Duration `yaml:"webhook_timeout"`
}

// Load reads path, expands ${ENV} vars, unmarshals YAML, and validates.
func Load(path string) (*Gateway, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %q: %w", path, err)
	}
	var cfg Gateway
	if err := yaml.Unmarshal([]byte(os.ExpandEnv(string(raw))), &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %q: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	cfg.applyDefaults()
	return &cfg, nil
}

func (g *Gateway) validate() error {
	var errs []string
	if g.Auth.JWKSURL == "" && len(g.Auth.HS256Secret) < 32 {
		errs = append(errs, "auth.hs256_secret must be at least 32 bytes")
	}
	if g.Auth.Issuer == "" {
		errs = append(errs, "auth.issuer is required")
	}
	if g.Auth.Audience == "" {
		errs = append(errs, "auth.audience is required")
	}
	if len(g.Backends) == 0 {
		errs = append(errs, "at least one backend is required")
	}
	for i, b := range g.Backends {
		if b.Name == "" {
			errs = append(errs, fmt.Sprintf("backends[%d].name is required", i))
		}
		if b.URL == "" {
			errs = append(errs, fmt.Sprintf("backends[%d].url is required", i))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (g *Gateway) applyDefaults() {
	if g.Listen == "" {
		g.Listen = ":8080"
	}
	if g.AdminListen == "" {
		g.AdminListen = "127.0.0.1:8081"
	}
	if g.Separator == "" {
		g.Separator = "/"
	}
	if g.Auth.Leeway == 0 {
		g.Auth.Leeway = 30 * time.Second
	}
	if g.HITL.ApprovalTTL == 0 {
		g.HITL.ApprovalTTL = 15 * time.Minute
	}
	if g.HITL.WebhookTimeout == 0 {
		g.HITL.WebhookTimeout = 5 * time.Second
	}
	if g.Logging.Format == "" {
		g.Logging.Format = "json"
	}
	if g.Logging.Level == "" {
		g.Logging.Level = "info"
	}
	for i := range g.Backends {
		if g.Backends[i].Timeout == 0 {
			g.Backends[i].Timeout = 30 * time.Second
		}
	}
}
