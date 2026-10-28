# Sentinel

Open-source control plane for AI agents: step-level policy, agent identity and sandboxed execution,
in a single Go binary you can run in front of Claude Code or Cursor.

**Status: pre-release.** Phase 1 (Shield) is in progress; Identity and Sandbox are not built yet.

| Component | Role | Phase | State |
|---|---|---|---|
| [`shield/`](shield) | MCP gateway + step-level policy engine | 1 | working baseline, hardening in progress |
| `identity/` | RFC 8693 token exchange, JWKS, revocation, audit | 2 | planned |
| `sandbox/` | Ephemeral microVM code execution | 3 | planned |

## Try it
```bash
export PATH="$HOME/sdk/go/bin:$PATH"          # if Go lives in ~/sdk
cd shield
export SENTINEL_HS256_SECRET="dev-secret-change-me-dev-secret-change-me"
export SENTINEL_ADMIN_TOKEN="dev-admin-token"
go test -race ./...
./examples/exploit-demo/demo.sh
```

## Read next
- [`docs/PLAN.md`](docs/PLAN.md): the plan, verified findings, what needs your approval
- [`docs/BRIEF.md`](docs/BRIEF.md): scope, market, architecture (source of truth)
- [`docs/threat-model.md`](docs/threat-model.md), [`docs/policy-reference.md`](docs/policy-reference.md), [`docs/adr/`](docs/adr)
- [`AGENTS.md`](AGENTS.md): invariants and rules for coding agents

License: Apache-2.0.
