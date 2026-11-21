package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yoosuf01/mcpguard/shield/internal/guard"
	"github.com/Yoosuf01/mcpguard/shield/internal/hitl"
	"github.com/Yoosuf01/mcpguard/shield/internal/identity"
	"github.com/Yoosuf01/mcpguard/shield/internal/policy"
	"github.com/Yoosuf01/mcpguard/shield/internal/telemetry"
)

// Fake Zoho CRM upstream server for automated unit & integration testing
func newFakeZohoServer(t *testing.T) *httptest.Server {
	t.Helper()
	db := map[string]map[string]any{
		"zc_98231": {
			"id":          "zc_98231",
			"name":        "Alice Vance",
			"company":     "Black Mesa Corp",
			"email":       "alice.vance@blackmesa.corp",
			"ssn":         "123-45-6789",
			"credit_card": "4111 1111 1111 1111",
			"deal_stage":  "Proposal",
		},
	}

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "server/discover":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"protocolVersion": "2026-07-28",
					"serverInfo":      map[string]any{"name": "zoho", "version": "1.0.0"},
					"cacheScope":      "private",
					"instructions":    "Zoho CRM MCP backend",
				},
			})
		case "tools/list":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"cacheScope": "private",
					"tools": []any{
						map[string]any{"name": "search_records", "description": "Search records"},
						map[string]any{"name": "update_contact", "description": "Update contact"},
						map[string]any{"name": "delete_contact", "description": "Delete contact"},
					},
				},
			})
		case "tools/call":
			switch req.Params.Name {
			case "search_records":
				recBytes, _ := json.Marshal(db["zc_98231"])
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"result": map[string]any{
						"content": []any{map[string]any{"type": "text", "text": string(recBytes)}},
					},
				})
			case "update_contact":
				field, _ := req.Params.Arguments["field"].(string)
				val, _ := req.Params.Arguments["value"].(string)
				db["zc_98231"][field] = val
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"result": map[string]any{
						"content": []any{map[string]any{"type": "text", "text": fmt.Sprintf("updated %s to %s", field, val)}},
					},
				})
			case "delete_contact":
				delete(db, "zc_98231")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"jsonrpc": "2.0",
					"id":      req.ID,
					"result": map[string]any{
						"content": []any{map[string]any{"type": "text", "text": "deleted"}},
					},
				})
			}
		}
	}))
}

func TestZohoCRM_ScopedIntegrationScenario(t *testing.T) {
	fakeZoho := newFakeZohoServer(t)
	defer fakeZoho.Close()

	policyYAML := `
version: "1"
default_action: deny
global:
  mask_in_results: ["credit_card", "ssn"]
  discovery:
    upstream_instructions: drop
    pin_tool_definitions: true
agents:
  - id: zoho-crm-sales-bot
    max_steps_per_session: 15
    tools:
      - name: zoho__search_records
        require_scope: "crm:read"
      - name: zoho__update_contact
        require_scope: "crm:write"
        require_approval: true
      - name: zoho__delete_contact
        deny: true
`
	pol, err := policy.Parse([]byte(policyYAML))
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	secret := "test-secret-at-least-32-bytes-long-for-hs256!"
	revocations := identity.NewMemoryRevocations()
	verifier := &identity.HS256Verifier{
		Secret:      []byte(secret),
		Issuer:      "https://test.auth.com",
		Audience:    "https://shield.test.com",
		Revocations: revocations,
		Leeway:      10 * time.Second,
	}

	approvals := hitl.NewStore(10 * time.Minute)
	engine := policy.NewEngine(pol, approvals)
	pins := guard.NewMemoryPins()

	gw := New(Options{
		ToolSeparator: "__",
		StrictHeaders: false,
		Backends: []*Backend{
			{Name: "zoho", URL: fakeZoho.URL, Timeout: 5 * time.Second},
		},
	}, engine, verifier, &telemetry.Memory{}, pins)

	// Step 1: Mint scoped agent token (sub=sales@example.com, act.sub=zoho-crm-sales-bot, scope=crm:read crm:write)
	token, err := identity.SignHS256([]byte(secret), map[string]any{
		"iss":   "https://test.auth.com",
		"aud":   "https://shield.test.com",
		"sub":   "sales@example.com",
		"act":   map[string]any{"sub": "zoho-crm-sales-bot"},
		"sid":   "sess-zoho-101",
		"scope": "crm:read crm:write",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(10 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignHS256 failed: %v", err)
	}

	// Helper to send JSON-RPC request to gateway
	callGW := func(authHeader string, method string, toolName string, params map[string]any) *httptest.ResponseRecorder {
		body := map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"method":  method,
		}
		if params != nil {
			body["params"] = params
		}
		bodyBytes, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		if authHeader != "" {
			req.Header.Set("Authorization", authHeader)
		}
		if toolName != "" {
			req.Header.Set("Mcp-Name", toolName)
		}
		req.Header.Set("Mcp-Method", method)

		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec
	}

	// 1. Unauthenticated call blocked (401)
	resUnauth := callGW("", "tools/call", "zoho__search_records", map[string]any{
		"name":      "zoho__search_records",
		"arguments": map[string]any{"query": "Alice"},
	})
	if resUnauth.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for unauthenticated request, got %d", resUnauth.Code)
	}

	// 2. Legitimate read allowed with PII masked
	resSearch := callGW("Bearer "+token, "tools/call", "zoho__search_records", map[string]any{
		"name":      "zoho__search_records",
		"arguments": map[string]any{"query": "Alice"},
	})
	if resSearch.Code != http.StatusOK {
		t.Fatalf("Expected 200 for search_records, got %d", resSearch.Code)
	}
	bodySearch := resSearch.Body.String()
	if !strings.Contains(bodySearch, "[REDACTED:ssn]") || !strings.Contains(bodySearch, "[REDACTED:credit_card]") {
		t.Errorf("Expected SSN and credit card redactions in search result, got: %s", bodySearch)
	}

	// 3. Dangerous delete explicitly denied
	resDelete := callGW("Bearer "+token, "tools/call", "zoho__delete_contact", map[string]any{
		"name":      "zoho__delete_contact",
		"arguments": map[string]any{"contact_id": "zc_98231"},
	})
	if !strings.Contains(resDelete.Body.String(), "explicitly denied") {
		t.Errorf("Expected explicit deny for delete_contact, got: %s", resDelete.Body.String())
	}

	// 4. Update deal stage requires human approval (pending)
	updateArgs := map[string]any{
		"name": "zoho__update_contact",
		"arguments": map[string]any{
			"contact_id": "zc_98231",
			"field":      "deal_stage",
			"value":      "Closed Won",
		},
	}
	resUpdate1 := callGW("Bearer "+token, "tools/call", "zoho__update_contact", updateArgs)
	if !strings.Contains(resUpdate1.Body.String(), "needs human approval") {
		t.Fatalf("Expected pending approval, got: %s", resUpdate1.Body.String())
	}

	// Extract approval ID from list
	pendingList := approvals.List()
	if len(pendingList) != 1 {
		t.Fatalf("Expected 1 pending approval, got %d", len(pendingList))
	}
	approvalID := pendingList[0].ID

	// 5. Admin approves via AdminHandler
	adminMux := gw.AdminHandler("admin-secret-token", revocations)
	approveReq := httptest.NewRequest(http.MethodPost, "/admin/approvals/"+approvalID+"/approve", nil)
	approveReq.Header.Set("Authorization", "Bearer admin-secret-token")
	adminRec := httptest.NewRecorder()
	adminMux.ServeHTTP(adminRec, approveReq)
	if adminRec.Code != http.StatusOK {
		t.Fatalf("Expected 200 for approval decision, got %d: %s", adminRec.Code, adminRec.Body.String())
	}

	// 6. Agent retries update -> Executed successfully
	resUpdate2 := callGW("Bearer "+token, "tools/call", "zoho__update_contact", updateArgs)
	if !strings.Contains(resUpdate2.Body.String(), "updated deal_stage to Closed Won") {
		t.Errorf("Expected update execution after approval, got: %s", resUpdate2.Body.String())
	}

	// 7. Single-use approval invariant (replaying exact same call is pending again)
	resUpdate3 := callGW("Bearer "+token, "tools/call", "zoho__update_contact", updateArgs)
	if !strings.Contains(resUpdate3.Body.String(), "needs human approval") {
		t.Errorf("Expected single-use approval to require re-approval, got: %s", resUpdate3.Body.String())
	}

	// 8. Kill switch revocation (rejected on next request)
	revocations.Revoke(context.Background(), "sess-zoho-101")
	resRevoked := callGW("Bearer "+token, "tools/call", "zoho__search_records", map[string]any{
		"name":      "zoho__search_records",
		"arguments": map[string]any{"query": "Alice"},
	})
	if resRevoked.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 for revoked session, got %d", resRevoked.Code)
	}
}
