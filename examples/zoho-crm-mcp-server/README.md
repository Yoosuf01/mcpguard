# Scoped Zoho CRM MCP Server Reference Integration

This example demonstrates the enterprise-grade zero-trust reference workflow for Model Context Protocol (MCP) agents interacting with CRM systems, specifically **Zoho CRM**:

> **"An AI agent that can update a CRM record only with a 10-minute scoped token, after a human sales manager approves the exact change, with a full structured audit trail."**

---

## 1. Security Architecture & Threat Defenses

```
[ AI Sales Agent ] 
       │
       │ Bearer Token: 10-min ES256/HS256 JWT
       │ Claims: sub=sales-manager, act.sub=zoho-sales-bot, scope=crm:read crm:write
       ▼
┌─────────────────────────────────────────────────────────────┐
│                 MCPGuard Shield Gateway                     │
│                                                             │
│  1. Token Authentication & Scope Verification               │
│  2. Step Budget & Rate Limiting                             │
│  3. Read Redaction: SSN, Credit Card, PII masked in output  │
│  4. Tool Policy: crm__delete_contact DENIED (Invariant #8)  │
│  5. HITL Gate: crm__update_contact requires Human Approval  │
│  6. Single-Use Invariant: Approval cannot be replayed (#9)  │
│  7. Real-time Revocation: Session kill switch (#11)         │
└─────────────────────────────────────────────────────────────┘
       │                               ▲
       │ Verified JSON-RPC             │ Human-in-the-Loop
       ▼                               │ Approval Decision
┌─────────────────────────┐     ┌─────────────────────────────┐
│   Zoho CRM MCP Server   │     │    Admin Approval Webhook   │
│  (Simulated or Live)    │     │   (Sales Manager Portal)    │
└─────────────────────────┘     └─────────────────────────────┘
```

### Security Invariants Demonstrated

1. **RFC 8693 Token Delegation**:
   - The token represents delegated authority: human principal `sub: alice@acme.corp`, agent identity `act.sub: zoho-crm-sales-bot`.
   - The agent's bearer token is strictly terminated at Shield and never forwarded upstream (Invariant #1).
2. **Deterministic Tool Boundaries**:
   - `zoho__delete_contact` is explicitly set to `deny: true`. Even if an LLM is hijacked via indirect prompt injection, explicit deny wins over any allow rules (Invariant #8).
3. **PII & Financial Data Masking**:
   - Customer SSNs and credit card numbers returned by `zoho__search_records` or `zoho__get_contact` are automatically redacted (`[REDACTED:ssn]`, `[REDACTED:credit_card]`) before reaching the model context.
4. **Single-Use Approvals (HITL)**:
   - When updating a deal stage or discount percentage, the call is placed in `pending` state with a unique `approval_id`.
   - Once a human manager approves the exact arguments via `/admin/approvals/{id}/approve`, the agent can proceed.
   - Any replay of the same approval or modification of arguments is blocked (Invariant #9).
5. **Real-Time Revocation Kill Switch**:
   - An administrator can instantly revoke `zoho-sales-session-42` via `/admin/revoke`. The very next tool-call attempt is blocked (Invariant #11).

---

## 2. Quickstart Demo

Run the automated end-to-end scenario script:

```bash
./examples/zoho-crm-mcp-server/run_demo.sh
```

### What Happens During the Demo:

1. **Unauthenticated Call**: Agent attempts to call `zoho__search_records` without a token $\rightarrow$ HTTP 401 Unauthorized.
2. **Token Minting**: Shield mints a 10-minute scoped token (`crm:read crm:write`).
3. **Discovery**: Shield exposes namespaced tools (`zoho__search_records`, `zoho__get_contact`, `zoho__update_contact`).
4. **Read Contact**: Agent searches for `Alice` $\rightarrow$ Allowed, with SSN and credit card numbers redacted.
5. **Delete Contact**: Agent attempts `zoho__delete_contact` $\rightarrow$ Blocked by policy (`tool_denied`).
6. **Update Deal Stage**: Agent calls `zoho__update_contact` with `deal_stage: Closed Won` $\rightarrow$ Intercepted as `pending` with `approval_id`.
7. **Manager Review**: Sales manager lists pending approvals via the Admin API (`GET /admin/approvals`).
8. **Manager Approval**: Sales manager approves the exact change (`POST /admin/approvals/{id}/approve`).
9. **Execution Retried**: Agent retries the update call $\rightarrow$ Allowed and updated in CRM!
10. **Replay Attempt**: Agent tries to alter another field with the used approval $\rightarrow$ Intercepted as a new pending approval (single-use enforced).
11. **Kill Switch**: Admin revokes session $\rightarrow$ Next request rejected immediately.
12. **Audit Trail**: Full structured audit log (`sentinel.step`) emitted for every action and decision.

---

## 3. Connecting to Live Zoho CRM Accounts

To connect this MCP server to a live Zoho CRM instance instead of the simulated backend:

1. Create a Self-Client in the [Zoho Developer Console](https://api-console.zoho.com/).
2. Generate an OAuth refresh token with scopes `ZohoCRM.modules.ALL` or `ZohoCRM.modules.contacts.ALL`.
3. Set environment variables:
   ```bash
   export ZOHO_CLIENT_ID="1000.xxxx"
   export ZOHO_CLIENT_SECRET="xxxx"
   export ZOHO_REFRESH_TOKEN="1000.xxxx"
   export ZOHO_API_DOMAIN="https://www.zohoapis.com"
   ```
4. Start `server.py` and run Shield with the same zero-trust policy.

