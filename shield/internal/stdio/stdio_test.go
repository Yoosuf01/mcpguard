package stdio

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProcess_CallAndEnvFilter(t *testing.T) {
	// Set an environment secret on the host
	_ = os.Setenv("SECRET_API_KEY_HOST", "super-secret-key-12345")
	_ = os.Setenv("ALLOWED_APP_VAR", "visible-value")
	defer func() {
		_ = os.Unsetenv("SECRET_API_KEY_HOST")
		_ = os.Unsetenv("ALLOWED_APP_VAR")
	}()

	// Python script acting as a stdio JSON-RPC MCP server
	pythonScript := `
import sys, json, os

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    req = json.loads(line)
    method = req.get("method")
    req_id = req.get("id")
    if method == "tools/call":
        secret = os.environ.get("SECRET_API_KEY_HOST", "")
        allowed = os.environ.get("ALLOWED_APP_VAR", "")
        res = {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "secret_leaked": secret != "",
                "allowed_received": allowed
            }
        }
        sys.stdout.write(json.dumps(res) + "\n")
        sys.stdout.flush()
`

	proc := NewProcess(Config{
		Command:      "python3",
		Args:         []string{"-c", pythonScript},
		Env:          []string{"ALLOWED_APP_VAR"},
		RestartPolicy: "never",
	})
	defer proc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := proc.Call(ctx, "tools/call", map[string]any{"name": "test"})
	if err != nil {
		t.Fatalf("Call failed: %v", err)
	}

	resultStr := string(resp.Result)
	if strings.Contains(resultStr, `"secret_leaked":true`) {
		t.Fatalf("SECURITY VIOLATION: host secret was leaked to child process: %s", resultStr)
	}
	if !strings.Contains(resultStr, "visible-value") {
		t.Errorf("expected allowed env var to be received, got result: %s", resultStr)
	}
}

func TestProcess_RestartOnFailure(t *testing.T) {
	// Script that crashes after first request
	pythonScript := `
import sys, json

for line in sys.stdin:
    req = json.loads(line)
    res = {"jsonrpc": "2.0", "id": req.get("id"), "result": {"status": "ok"}}
    sys.stdout.write(json.dumps(res) + "\n")
    sys.stdout.flush()
    sys.exit(1) # crash immediately after
`

	proc := NewProcess(Config{
		Command:       "python3",
		Args:          []string{"-c", pythonScript},
		RestartPolicy: "on_failure",
	})
	defer proc.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// First call succeeds then script exits 1
	r1, err := proc.Call(ctx, "ping", nil)
	if err != nil {
		t.Fatalf("first call failed: %v", err)
	}
	if !strings.Contains(string(r1.Result), "ok") {
		t.Errorf("unexpected r1 result: %s", string(r1.Result))
	}

	// Second call should restart the process and succeed
	r2, err := proc.Call(ctx, "ping", nil)
	if err != nil {
		t.Fatalf("second call failed to restart: %v", err)
	}
	if !strings.Contains(string(r2.Result), "ok") {
		t.Errorf("unexpected r2 result: %s", string(r2.Result))
	}
}
