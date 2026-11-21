#!/usr/bin/env bash
# Reference Scenario: Scoped Zoho CRM Agent with Human-in-the-Loop Gate
#
# Scenario Story:
# An enterprise sales bot requests a 10-minute delegated token (RFC 8693).
# It can search contacts (read-only with PII masked), cannot delete contacts
# (explicitly blocked by policy), and can update deal stages ONLY after
# a human sales manager approves the exact change.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export PATH="$HOME/sdk/go/bin:$PATH"

echo "=================================================================="
echo " MCPGuard: Real-World Scoped Zoho CRM MCP Integration Demo"
echo "=================================================================="

# 1. Build Shield binary
(cd "$REPO_ROOT/shield" && go build -o bin/shield ./cmd/shield)
cd "$REPO_ROOT"

# 2. Start Python Zoho CRM MCP Server (:9003)
python3 "$REPO_ROOT/examples/zoho-crm-mcp-server/server.py" 9003 >/tmp/zoho-crm-mcp.log 2>&1 &
ZOHO_PID=$!

# 3. Start MCPGuard Shield Gateway (:8080, admin: :8081)
./shield/bin/shield -config "$REPO_ROOT/examples/zoho-crm-mcp-server/shield.yaml" >/tmp/zoho-shield.log 2>&1 &
SHIELD_PID=$!

cleanup() {
  echo -e "\nShutting down demo background services..."
  kill $ZOHO_PID $SHIELD_PID 2>/dev/null || true
}
trap cleanup EXIT

# 4. Wait for readiness
wait_http() {
  local url=$1 label=$2
  local deadline=$((SECONDS + 20))
  until curl -sf --max-time 1 "$url" >/dev/null 2>&1; do
    if [[ $SECONDS -ge $deadline ]]; then
      echo "ERROR: $label did not start within 20s" >&2
      exit 1
    fi
    sleep 0.1
  done
}

wait_http "http://127.0.0.1:8080/healthz" "MCPGuard Gateway"

echo "Services ready: Zoho CRM MCP (:9003), MCPGuard (:8080, :8081)"

hr() { printf '\n\033[1;34m== %s ==\033[0m\n' "$1"; }

# -------------------------------------------------------------------------
hr "Step 1: Unauthenticated agent call blocked (401 Unauthorized)"
# -------------------------------------------------------------------------
curl -s -w "\nHTTP Status: %{http_code}\n" http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"server/discover"}'

# -------------------------------------------------------------------------
hr "Step 2: Mint 10-minute delegated agent token (sub=alice, act=zoho-crm-sales-bot)"
# -------------------------------------------------------------------------
TOKEN=$(./shield/bin/shield -config "$REPO_ROOT/examples/zoho-crm-mcp-server/shield.yaml" \
  -mint \
  -sub "alice@acme.corp" \
  -agent "zoho-crm-sales-bot" \
  -scope "crm:read crm:write" \
  -sid "zoho-sales-session-42" \
  -ttl 10m)

echo "Minted 10-minute Scoped JWT: ${TOKEN:0:35}...${TOKEN: -20}"

shield_call() {
  curl -s http://127.0.0.1:8080/mcp \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $TOKEN" \
    -H 'MCP-Protocol-Version: 2026-07-28' \
    -H "Mcp-Method: $1" \
    ${2:+-H "Mcp-Name: $2"} \
    -d "$3"
  echo
}

# -------------------------------------------------------------------------
hr "Step 3: Discovery & Tool Listing (Namespaced as zoho__*)"
# -------------------------------------------------------------------------
shield_call "tools/list" "" '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'

# -------------------------------------------------------------------------
hr "Step 4: Legitimate read permitted (PII masked: card and ssn redacted)"
# -------------------------------------------------------------------------
shield_call "tools/call" "zoho__search_records" \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"zoho__search_records","arguments":{"query":"Alice"}}}'

# -------------------------------------------------------------------------
hr "Step 5: Dangerous delete operation denied (Security Invariant #8)"
# -------------------------------------------------------------------------
shield_call "tools/call" "zoho__delete_contact" \
  '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"zoho__delete_contact","arguments":{"contact_id":"zc_98231"}}}'

# -------------------------------------------------------------------------
hr "Step 6: Update deal stage intercepted for human approval"
# -------------------------------------------------------------------------
UPDATE_RESP=$(curl -s http://127.0.0.1:8080/mcp \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H "Mcp-Method: tools/call" \
  -H "Mcp-Name: zoho__update_contact" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"zoho__update_contact","arguments":{"contact_id":"zc_98231","field":"deal_stage","value":"Closed Won"}}}')

echo "$UPDATE_RESP"

APPROVAL_ID=$(echo "$UPDATE_RESP" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('result', {}).get('_meta', {}).get('dev.sentinel/approval_id', ''))")
echo "Pending Approval ID: $APPROVAL_ID"

# -------------------------------------------------------------------------
hr "Step 7: Sales manager inspects pending approvals in admin API"
# -------------------------------------------------------------------------
curl -s http://127.0.0.1:8081/admin/approvals \
  -H "Authorization: Bearer demo-admin-token-secret"
echo

# -------------------------------------------------------------------------
hr "Step 8: Sales manager approves the exact change (Closed Won)"
# -------------------------------------------------------------------------
curl -s -X POST "http://127.0.0.1:8081/admin/approvals/$APPROVAL_ID/approve" \
  -H "Authorization: Bearer demo-admin-token-secret"
echo

# -------------------------------------------------------------------------
hr "Step 9: Agent retries with approved change -> Successfully executed"
# -------------------------------------------------------------------------
shield_call "tools/call" "zoho__update_contact" \
  '{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"zoho__update_contact","arguments":{"contact_id":"zc_98231","field":"deal_stage","value":"Closed Won"}}}'

# -------------------------------------------------------------------------
hr "Step 10: Approval single-use enforcement (Security Invariant #9)"
# -------------------------------------------------------------------------
echo "Agent attempts to replay previous approval for a different field value..."
shield_call "tools/call" "zoho__update_contact" \
  '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"zoho__update_contact","arguments":{"contact_id":"zc_98231","field":"deal_stage","value":"Closed Lost"}}}'

# -------------------------------------------------------------------------
hr "Step 11: Real-time Kill Switch Revocation (Security Invariant #11)"
# -------------------------------------------------------------------------
curl -s -X POST http://127.0.0.1:8081/admin/revoke \
  -H "Authorization: Bearer demo-admin-token-secret" \
  -H 'Content-Type: application/json' \
  -d '{"session_id":"zoho-sales-session-42"}'
echo

echo "Session revoked. Next request rejected immediately:"
shield_call "tools/call" "zoho__search_records" \
  '{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"zoho__search_records","arguments":{"query":"Alice"}}}'

# -------------------------------------------------------------------------
hr "Step 12: Structured Audit Trail Emitted"
# -------------------------------------------------------------------------
tail -n 10 /tmp/zoho-shield.log
echo -e "\nDemo completed successfully!"
