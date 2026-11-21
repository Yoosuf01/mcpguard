package gateway

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestAdminHandler_SentinelConsoleAndEndpoints(t *testing.T) {
	polYAML := `
version: "1"
default_action: allow
`
	pol, err := policy.Parse([]byte(polYAML))
	if err != nil {
		t.Fatalf("policy.Parse failed: %v", err)
	}

	approvals := hitl.NewStore(time.Minute)
	engine := policy.NewEngine(pol, approvals)
	revocations := identity.NewMemoryRevocations()
	pins := guard.NewMemoryPins()
	pins.Set("postgres__query", "sha256-abc123mockhash")

	adminToken := "secret-admin-token-123"
	gw := New(Options{}, engine, nil, &telemetry.Memory{}, pins)
	handler := gw.AdminHandler(adminToken, revocations)

	// Add an event to audit log for testing
	gw.record(context.Background(), &identity.Principal{AgentID: "agent-007", Subject: "user@corp", SessionID: "sess-99"}, telemetry.Event{
		Kind:     "tools/call",
		Tool:     "test_tool",
		Decision: "allow",
		Rule:     "allow",
	})

	// 1. GET /admin/console (Console HTML)
	t.Run("ConsoleHTML_Root", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/console", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for /admin/console, got %d", rec.Code)
		}
		ct := rec.Header().Get("Content-Type")
		if !strings.Contains(ct, "text/html") {
			t.Errorf("Expected text/html content type, got %s", ct)
		}
		if rec.Header().Get("X-Frame-Options") != "DENY" {
			t.Errorf("Missing X-Frame-Options: DENY header")
		}
		if !strings.Contains(rec.Body.String(), "MCPGuard Sentinel Console") {
			t.Errorf("Console HTML missing branding title")
		}
	})

	// 2. GET /admin/ (Redirect or direct console serve)
	t.Run("ConsoleHTML_Slash", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 OK for /admin/, got %d", rec.Code)
		}
	})

	// 3. GET /admin/approvals (Auth required)
	t.Run("ApprovalsAuth", func(t *testing.T) {
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/admin/approvals", nil)
		recNoAuth := httptest.NewRecorder()
		handler.ServeHTTP(recNoAuth, reqNoAuth)
		if recNoAuth.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized without token, got %d", recNoAuth.Code)
		}

		reqAuth := httptest.NewRequest(http.MethodGet, "/admin/approvals", nil)
		reqAuth.Header.Set("Authorization", "Bearer "+adminToken)
		recAuth := httptest.NewRecorder()
		handler.ServeHTTP(recAuth, reqAuth)
		if recAuth.Code != http.StatusOK {
			t.Errorf("Expected 200 OK with token, got %d", recAuth.Code)
		}
	})

	// 4. GET /admin/audit
	t.Run("AuditLogEndpoint", func(t *testing.T) {
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
		recNoAuth := httptest.NewRecorder()
		handler.ServeHTTP(recNoAuth, reqNoAuth)
		if recNoAuth.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized without token, got %d", recNoAuth.Code)
		}

		reqAuth := httptest.NewRequest(http.MethodGet, "/admin/audit", nil)
		reqAuth.Header.Set("Authorization", "Bearer "+adminToken)
		recAuth := httptest.NewRecorder()
		handler.ServeHTTP(recAuth, reqAuth)
		if recAuth.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK with token, got %d", recAuth.Code)
		}

		var events []telemetry.Event
		if err := json.Unmarshal(recAuth.Body.Bytes(), &events); err != nil {
			t.Fatalf("Failed to parse audit events JSON: %v", err)
		}
		if len(events) != 1 {
			t.Fatalf("Expected 1 audit event, got %d", len(events))
		}
		if events[0].AgentID != "agent-007" || events[0].Tool != "test_tool" {
			t.Errorf("Unexpected event contents: %+v", events[0])
		}
	})

	// 5. GET /admin/pins
	t.Run("PinsEndpoint", func(t *testing.T) {
		reqNoAuth := httptest.NewRequest(http.MethodGet, "/admin/pins", nil)
		recNoAuth := httptest.NewRecorder()
		handler.ServeHTTP(recNoAuth, reqNoAuth)
		if recNoAuth.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 Unauthorized without token, got %d", recNoAuth.Code)
		}

		reqAuth := httptest.NewRequest(http.MethodGet, "/admin/pins", nil)
		reqAuth.Header.Set("Authorization", "Bearer "+adminToken)
		recAuth := httptest.NewRecorder()
		handler.ServeHTTP(recAuth, reqAuth)
		if recAuth.Code != http.StatusOK {
			t.Fatalf("Expected 200 OK with token, got %d", recAuth.Code)
		}

		var pinsMap map[string]string
		if err := json.Unmarshal(recAuth.Body.Bytes(), &pinsMap); err != nil {
			t.Fatalf("Failed to parse pins JSON: %v", err)
		}
		if pinsMap["postgres__query"] != "sha256-abc123mockhash" {
			t.Errorf("Expected pinned hash for postgres__query, got %s", pinsMap["postgres__query"])
		}
	})

	// 6. POST /admin/revoke
	t.Run("RevocationEndpoint", func(t *testing.T) {
		body := bytes.NewBufferString(`{"session_id":"sess-to-kill"}`)
		req := httptest.NewRequest(http.MethodPost, "/admin/revoke", body)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("Expected 200 OK on revoke, got %d", rec.Code)
		}
		if !revocations.IsRevoked(context.Background(), "sess-to-kill") {
			t.Errorf("Session sess-to-kill was not revoked")
		}
	})
}
