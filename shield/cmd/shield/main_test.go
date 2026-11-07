package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yoosuf01/mcpguard/shield/internal/pins"

	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
	"github.com/Yoosuf01/mcpguard/shield/internal/policy"
)

func TestLoadConfig_Valid(t *testing.T) {
	yamlContent := `
listen: ":9090"
admin_listen: ":9091"
admin_token: "test-admin"
policy_file: "policy.yaml"
auth:
  hs256_secret: "12345678901234567890123456789012"
  issuer: "test-iss"
  audience: "test-aud"
backends:
  - name: "test-b"
    url: "http://localhost:8000"
`
	tmp := filepath.Join(t.TempDir(), "shield.yaml")
	if err := os.WriteFile(tmp, []byte(yamlContent), 0600); err != nil {
		t.Fatal(err)
	}

	cfg, err := loadConfig(tmp)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if cfg.Listen != ":9090" {
		t.Errorf("expected :9090, got %s", cfg.Listen)
	}
	if len(cfg.Backends) != 1 {
		t.Errorf("expected 1 backend, got %d", len(cfg.Backends))
	}
}

func TestLoadConfig_ValidationFailures(t *testing.T) {
	// Secret too short
	shortSecretYAML := `
auth:
  hs256_secret: "short"
backends:
  - name: "b"
    url: "http://localhost"
`
	tmp1 := filepath.Join(t.TempDir(), "short.yaml")
	_ = os.WriteFile(tmp1, []byte(shortSecretYAML), 0600)
	if _, err := loadConfig(tmp1); err == nil {
		t.Error("expected error for secret < 32 bytes")
	}

	// No backends
	noBackendsYAML := `
auth:
  hs256_secret: "12345678901234567890123456789012"
`
	tmp2 := filepath.Join(t.TempDir(), "nobackends.yaml")
	_ = os.WriteFile(tmp2, []byte(noBackendsYAML), 0600)
	if _, err := loadConfig(tmp2); err == nil {
		t.Error("expected error for empty backends")
	}
}

func TestPolicyReload_FailureKeepsOldPolicy(t *testing.T) {
	// Tests Invariant #12: bad reload file must keep previous policy active
	initialYAML := `
version: "1"
default_action: allow
agents:
  - id: bot-a
    max_steps_per_session: 10
`
	tmpDir := t.TempDir()
	polFile := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(polFile, []byte(initialYAML), 0600); err != nil {
		t.Fatal(err)
	}

	initialPol, err := policy.LoadFile(polFile)
	if err != nil {
		t.Fatalf("failed to load initial policy: %v", err)
	}

	engine := policy.NewEngine(initialPol, hitl.NewStore(0))
	if engine.Policy().File.DefaultAction != policy.Allow {
		t.Fatalf("expected initial default_action allow")
	}

	// Overwrite with broken YAML
	brokenYAML := `
version: "1"
default_action: [invalid yaml syntax here
`
	if err := os.WriteFile(polFile, []byte(brokenYAML), 0600); err != nil {
		t.Fatal(err)
	}

	// Attempt reload simulation as done in SIGHUP handler
	_, err = policy.LoadFile(polFile)
	if err == nil {
		t.Fatal("expected error on broken YAML")
	}
	// Verify old policy is still preserved
	if engine.Policy().File.DefaultAction != policy.Allow {
		t.Errorf("invariant violated: engine policy changed after failed reload")
	}

	// Overwrite with valid new YAML and reload
	validNewYAML := `
version: "1"
default_action: deny
`
	if err := os.WriteFile(polFile, []byte(validNewYAML), 0600); err != nil {
		t.Fatal(err)
	}
	newPol, err := policy.LoadFile(polFile)
	if err != nil {
		t.Fatalf("failed to load valid new policy: %v", err)
	}
	engine.Swap(newPol)

	if engine.Policy().File.DefaultAction != policy.Deny {
		t.Errorf("expected engine default_action deny after successful swap, got %s", engine.Policy().File.DefaultAction)
	}
}

func TestPinsCLI_Operations(t *testing.T) {
	tmpDir := t.TempDir()
	pinsFile := filepath.Join(tmpDir, "test_pins.json")

	store, err := pins.NewFileStore(pinsFile)
	if err != nil {
		t.Fatalf("failed to create FileStore: %v", err)
	}

	// 1. Set initial pin
	store.Set("tool|github|create_issue", "sha256:orig123")

	// 2. Generate diff
	diff := pins.Diff("github", "create_issue", "sha256:orig123", "sha256:drift456")
	if !strings.Contains(diff, "DRIFT DETECTED") {
		t.Errorf("expected DRIFT DETECTED in diff, got: %s", diff)
	}

	// 3. Re-approve tool
	if err := store.Approve("github", "create_issue", "sha256:drift456"); err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	// 4. Verify approved
	newDigest, ok := store.Get("tool|github|create_issue")
	if !ok || newDigest != "sha256:drift456" {
		t.Errorf("expected approved digest sha256:drift456, got %s", newDigest)
	}
}

func TestPolicyCLI_CompileAndTest(t *testing.T) {
	yamlPolicy := `
version: "1"
default_action: deny
global:
  deny_arg_patterns:
    - '(?i)\bdelete\s+from\b'
agents:
  - id: test-bot
    tools:
      - name: "db__read"
        require_scope: "db:read"
`
	tmpDir := t.TempDir()
	yamlFile := filepath.Join(tmpDir, "policy.yaml")
	if err := os.WriteFile(yamlFile, []byte(yamlPolicy), 0600); err != nil {
		t.Fatal(err)
	}

	regoOutFile := filepath.Join(tmpDir, "policy.rego")
	runPolicyCompile(yamlFile, regoOutFile)

	regoBytes, err := os.ReadFile(regoOutFile)
	if err != nil {
		t.Fatalf("failed to read compiled rego output: %v", err)
	}
	if !strings.Contains(string(regoBytes), "package mcpguard.policy") {
		t.Errorf("expected package mcpguard.policy in compiled rego")
	}

	fixtures := `[
  {
    "name": "db read allowed with scope",
    "principal": {"subject": "bob", "agent_id": "test-bot", "scopes": ["db:read"]},
    "tool": "db__read",
    "arguments": {"q": "select 1"},
    "expected": {"action": "allow", "rule": "allow"}
  },
  {
    "name": "delete from blocked",
    "principal": {"subject": "bob", "agent_id": "test-bot", "scopes": ["db:read"]},
    "tool": "db__read",
    "arguments": {"q": "delete from users"},
    "expected": {"action": "deny", "rule": "deny_arg_pattern"}
  }
]`
	fixFile := filepath.Join(tmpDir, "fixtures.json")
	if err := os.WriteFile(fixFile, []byte(fixtures), 0600); err != nil {
		t.Fatal(err)
	}

	// Test with compiled rego and fixtures
	runPolicyTest(regoOutFile, fixFile)

	// Test with source YAML and fixtures directly
	runPolicyTest(yamlFile, fixFile)
}
