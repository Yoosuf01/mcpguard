package config_test

import (
	"os"
	"strings"
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/config"
)

func tmp(t *testing.T, s string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(s)
	f.Close()
	return f.Name()
}

func TestLoadValid(t *testing.T) {
	cfg, err := config.Load(tmp(t, `
auth:
  hs256_secret: "this-is-a-long-enough-secret-32b"
  issuer: "https://id.local"
  audience: "mcpguard"
backends:
  - name: tools
    url: http://localhost:9000
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Listen != ":8080" {
		t.Errorf("default listen not applied, got %q", cfg.Listen)
	}
}

func TestLoadJWKSValid(t *testing.T) {
	cfg, err := config.Load(tmp(t, `
auth:
  jwks_url: "https://id.local/.well-known/jwks.json"
  issuer: "https://id.local"
  audience: "mcpguard"
backends:
  - name: tools
    url: http://localhost:9000
`))
	if err != nil {
		t.Fatalf("unexpected error with jwks_url: %v", err)
	}
	if cfg.Auth.JWKSURL != "https://id.local/.well-known/jwks.json" {
		t.Errorf("expected jwks_url set, got %q", cfg.Auth.JWKSURL)
	}
}

func TestShortSecret(t *testing.T) {
	_, err := config.Load(tmp(t, `
auth:
  hs256_secret: "tooshort"
  issuer: "x"
  audience: "y"
backends:
  - name: b
    url: http://localhost:9000
`))
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected 32-byte error, got %v", err)
	}
}

func TestNoBackends(t *testing.T) {
	_, err := config.Load(tmp(t, `
auth:
  hs256_secret: "this-is-a-long-enough-secret-32b"
  issuer: "x"
  audience: "y"
`))
	if err == nil || !strings.Contains(err.Error(), "backend") {
		t.Fatalf("expected backend error, got %v", err)
	}
}

func TestEnvExpansion(t *testing.T) {
	t.Setenv("MY_SECRET", "this-is-a-long-enough-secret-32b")
	cfg, err := config.Load(tmp(t, `
auth:
  hs256_secret: "${MY_SECRET}"
  issuer: "x"
  audience: "y"
backends:
  - name: b
    url: http://localhost:9000
`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Auth.HS256Secret != "this-is-a-long-enough-secret-32b" {
		t.Fatalf("env expansion failed: %q", cfg.Auth.HS256Secret)
	}
}
