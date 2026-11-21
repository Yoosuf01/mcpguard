package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/guard"
	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
	"github.com/Yoosuf01/mcpguard/shield/internal/identity"
	"github.com/Yoosuf01/mcpguard/shield/internal/policy"
	"github.com/Yoosuf01/mcpguard/shield/internal/telemetry"
)

func BenchmarkGateway_AllowedCall(b *testing.B) {
	// Fast in-memory mock upstream responding with immediate JSON
	fastUp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"result"}]}}`))
	}))
	defer fastUp.Close()

	polBytes, err := os.ReadFile("../../configs/policy.yaml")
	if err != nil {
		b.Fatal(err)
	}
	yamlStr := strings.Replace(string(polBytes), "max_steps_per_session: 25", "max_steps_per_session: 0", 1)
	yamlStr = strings.Replace(yamlStr, "rate_limit_per_minute: 60", "rate_limit_per_minute: 0", 1)
	pol, err := policy.Parse([]byte(yamlStr))
	if err != nil {
		b.Fatal(err)
	}

	engine := policy.NewEngine(pol, hitl.NewStore(time.Hour))
	verifier := &identity.HS256Verifier{
		Secret:   secret,
		Issuer:   "iss",
		Audience: "shield",
	}

	opts := Options{
		Backends: []*Backend{
			{Name: "postgres", URL: fastUp.URL},
		},
	}
	gw := New(opts, engine, verifier, &telemetry.Memory{}, guard.NewMemoryPins())

	tok, err := identity.SignHS256(secret, map[string]any{
		"iss":   "iss",
		"aud":   "shield",
		"sub":   "alice",
		"act":   map[string]any{"sub": "customer-support-bot"},
		"sid":   "s_bench",
		"scope": "db:read",
		"exp":   time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		b.Fatal(err)
	}

	reqBody, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "postgres__query",
			"arguments": map[string]any{
				"sql": "SELECT id, name FROM users WHERE active = true LIMIT 10",
			},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("MCP-Protocol-Version", ProtoStateless)
		req.Header.Set("Mcp-Name", "postgres__query")

		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			b.Fatalf("expected 200 OK, got %d", rr.Code)
		}
	}
}

func BenchmarkPolicy_Evaluate(b *testing.B) {
	polBytes, _ := os.ReadFile("../../configs/policy.yaml")
	yamlStr := strings.Replace(string(polBytes), "max_steps_per_session: 25", "max_steps_per_session: 0", 1)
	yamlStr = strings.Replace(yamlStr, "rate_limit_per_minute: 60", "rate_limit_per_minute: 0", 1)
	pol, _ := policy.Parse([]byte(yamlStr))
	engine := policy.NewEngine(pol, hitl.NewStore(time.Hour))

	p := &identity.Principal{
		Subject:   "alice",
		AgentID:   "customer-support-bot",
		SessionID: "s_bench_eval",
		Scopes:    []string{"db:read"},
	}
	args := map[string]any{
		"sql": "SELECT id, name FROM users WHERE active = true LIMIT 10",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		d := engine.Evaluate(p, "postgres__query", args)
		if d.Action != policy.Allow {
			b.Fatalf("expected allow, got %s (rule=%s, reason=%s)", d.Action, d.Rule, d.Reason)
		}
	}
}
