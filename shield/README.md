# MCPGuard Shield

Open-source zero-trust gateway for MCP agents: one Go binary that sits between your agent (Claude Code, Cursor, LangGraph...) and its MCP servers and evaluates **every step** of the agent loop.

- Blocks the MCP-2026-015 (server `instructions` injection) + MCP-2026-008 (public cache poisoning) chain
- Tool allowlists, required scopes, deny patterns, egress/SSRF control, credential-exfiltration checks
- Tool-definition pinning (rug pulls) and poisoned-tool quarantine
- PII/secret redaction and indirect-prompt-injection flagging on tool output
- Human approval for sensitive tools, per-session step limits, instant kill switch
- One structured audit event per step

```bash
export MCPGUARD_HS256_SECRET="dev-secret-change-me-dev-secret-change-me"
export MCPGUARD_ADMIN_TOKEN="dev-admin-token"
go test -race ./...
./examples/exploit-demo/demo.sh
```

See [`../docs/PLAN.md`](../docs/PLAN.md), [`../docs/policy-reference.md`](../docs/policy-reference.md), and [`../docs/threat-model.md`](../docs/threat-model.md) for architecture, threat model, roadmap and the policy reference. License: Apache-2.0.
