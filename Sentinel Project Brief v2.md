# Project Brief v2: "Sentinel" — Open-Source Agentic Control Plane
### Shield-first build: MCP Gateway + Step-Level Policy Engine (Shield), then Agent Identity, then Sandbox

Version 2 — October 2026. Replaces v1. Changes from v1:
- Gateway (#1) and Policy (#2) are merged into one launch artifact, **Sentinel Shield**, and built first.
- Identity (#4) moves to Phase 2, Sandbox (#3) to Phase 3. All four are still in scope.
- Adds verified market validation, a competitor map, and a threat model anchored on two real, open MCP spec issues (MCP-2026-015 and MCP-2026-008).
- Targets the MCP 2026-07-28 spec (stateless, routing headers, `cacheScope`), with support for older session-based servers.
- Ships with working, tested Go code for the Shield interception layer (`shield/`). Phase 1 starts from a running baseline, not a blank repo.

---

## 0. How to use this document

1. Unzip `sentinel-shield.zip` into a new repo. The tree is `sentinel/SENTINEL_BRIEF.md` (this file) plus `sentinel/shield/` (working Go code).
2. Open the repo in Claude Code / Cursor / Antigravity / Codex and paste this as your first message:

> Read `SENTINEL_BRIEF.md` fully, then read every file under `shield/`. Run `go test -race ./...` and `./examples/exploit-demo/demo.sh` from `shield/` and confirm both pass. Do not change any behavior covered by the "Security invariants" in section 7.3 without adding a test first. Then propose a plan for the Phase 1 backlog in section 9.1, one PR-sized task at a time, and wait for my approval before writing code.

3. Keep this file in the repo root as `docs/BRIEF.md`. It is the source of truth the agent should re-read when it loses context.

---

## 1. Origin & market thesis

### 1.1 What WSO2 did
WSO2 started as an API management and integration middleware vendor. In 2026 it rebuilt its strategy around the control-plane layer that lets enterprises run autonomous agents safely. The flagship is **WSO2 Agent Manager**: beta in May 2026, generally available September 15, 2026, released under Apache 2.0, and deployable self-hosted or as SaaS ([WSO2 GA announcement](https://wso2.com/about/news/wso2-agent-manager-sovereign-ai-governance/), [WSO2 beta announcement](https://wso2.com/about/news/wso2-launches-agent-manager/)).

Its GA capability list is effectively the blueprint for Sentinel ([WSO2 GA announcement](https://wso2.com/about/news/wso2-agent-manager-sovereign-ai-governance/)):

| WSO2 capability | What it does | Sentinel component |
|---|---|---|
| Federated agent management | One inventory for every agent, on any model or framework | Shield (agent profiles in policy) + Identity (registry) |
| Agent identity & security | Verifiable identity, RBAC, delegation, token exchange, instant revocation | **Sentinel Identity** |
| 40+ guardrails at agent, MCP and LLM levels | PII masking, rate limiting, URL/content validation, prompt validation, mapped to OWASP Top 10 ([Agent Manager page](https://wso2.com/agent-platform/agent-manager/)) | **Sentinel Shield** |
| Observability & evaluation | End-to-end OpenTelemetry tracing | Shield telemetry, then OTel |
| Sandboxed runtime | Kubernetes-native sandboxed execution with real-time suspension | **Sentinel Sandbox** |
| AI Gateway + Agent ID | Governs LLM, MCP and A2A traffic; registers agents as first-class identities ([WSO2 Agent Platform](https://wso2.com/agent-platform/)) | Shield + Identity |

WSO2's own framing of the gateway is the core thesis of Shield: every agent calls LLMs and tools, both leave the agent process, and "per-agent code can't enforce org-wide policy. The gateway can" ([WSO2Con 2026 slides](https://wso2.com/files/wso2con2026usa/slides/ai-agent-manager-part-2.pdf)).

### 1.2 Where the gap actually is (corrected from v1)
v1 said there is no self-hosted equivalent. That is wrong: WSO2 Agent Manager is itself open source. The real gap is narrower and still large:

- WSO2 Agent Manager runs internal agents on OpenChoreo and is Kubernetes-native ([WSO2 docs](https://wso2.com/agent-platform/docs/cloud/get-started/what-is-amp/)). It is a platform to adopt, not a binary to drop in.
- The funded OSS competitors are also Kubernetes-first or licensed in ways enterprises hesitate over (see 1.3).
- Nobody ships one small, Apache-2.0, single-binary Go control plane that does **step-level policy + agent identity + sandboxed execution** together and runs in front of Claude Code or Cursor in five minutes.

Positioning line: *"Sentinel is the open-source control plane for AI agents: what WSO2 Agent Manager does for enterprises, in a single Go binary you can run in front of Claude Code in five minutes."*

### 1.3 Market validation (verified, October 2026)

| Player | What it is | Funding / license | What Sentinel does differently |
|---|---|---|---|
| **Archestra** (London) | OSS platform giving agents governed access to corporate data. Private MCP registry, deterministic tool-invocation policies, MCP servers run as isolated K8s pods | $10M seed led by 20VC in June 2026, $13.5M total ([Archestra blog](https://archestra.ai/blog/archestra-announces-10m-seed)). Core under AGPL-3.0, K8s-native ([Cyber Company Profiles](https://cybercompanyprofiles.com/companies/archestra)) | Apache 2.0 (no AGPL concern), no Kubernetes needed, Go single binary |
| **Lasso Security** | Open-source, plugin-based MCP gateway in Python. Intercepts requests and responses to sanitize sensitive data; paid Lasso guardrail plugin | Launched April 15, 2025 ([Lasso press release](https://www.lasso.security/resources/lasso-releases-first-open-source-security-gateway-for-mcp)), MIT ([GitHub](https://github.com/lasso-security/mcp-gateway)) | Step-level policy-as-code, agent identity and scopes, sandbox, Go performance |
| **Runlayer** | Commercial MCP gateway + AI control plane: identity-aware policy, ToolGuard scanning, audit | From the team that built Zapier MCP, backed by Khosla and Felicis ([Runlayer](https://www.runlayer.com/llms/unified-mcp-platform-vs-fragmented-agent-stack)) | Fully open source and self-hostable |
| **WSO2 Agent Manager** | Full enterprise control plane | Apache 2.0, K8s/OpenChoreo ([WSO2 Agent Platform architecture](https://wso2.com/api-platform/learn/agent-platform-architecture/)) | Lightweight, not a platform migration |

Takeaway: the problem is validated by funded companies, and a funded company (Archestra) already ships near-identical positioning. **Speed and a sharp wedge matter more than breadth on day one.** That is why Shield launches first, and why the four-part combination is the long-term moat rather than the launch message.

---

## 2. Threat model anchor: why now

The MCP 2026-07-28 spec rewrite made the gateway the natural enforcement point, and also opened two attack paths that were still open in September 2026. These are the core of your launch demo.

### 2.1 Spec changes a gateway must handle
Per the [APS-2026-01 advisory on MCP 2026-07-28](https://github.com/Moai-Team-LLC/agentic-product-standard/blob/main/docs/advisories/APS-2026-01-mcp-2026-07-28.md):
- **Stateless protocol**: `initialize` and `Mcp-Session-Id` are removed; version and capabilities travel per request.
- **Routing headers**: `Mcp-Method` on every request, `Mcp-Name` on `tools/call`, `resources/read`, `prompts/get`. Servers must reject a header that disagrees with the body, and policy-enforcing gateways should reject requests where `MCP-Protocol-Version` is missing or too old.
- **Caching hints**: list/read results carry `ttlMs` and `cacheScope` (`public` | `private`). Private results must not be shared across authorization contexts.

### 2.2 MCP-2026-015: server `instructions` → system prompt injection
Any MCP server can return an `instructions` field at discovery, which clients fold into the model's system prompt. The issue describes it as fully server-controlled, "with no sanitization, validation, or length limits" ([Datapace analysis](https://datapace.ai/blog/mcp-cache-poisoning-prompt-injection)). The attack lands **before the first tool call**, and the issue was still open as of September 18, 2026 ([RuntimeWire](https://runtimewire.com/article/mcp-prompt-injection-before-first-tool-call)).

### 2.3 MCP-2026-008: cache poisoning across users
The server declares `cacheScope` and nothing verifies it. A malicious server marks a poisoned `tools/list` or discovery response as `public`, and any shared cache or gateway is invited to serve it to every user behind it ([Datapace analysis](https://datapace.ai/blog/mcp-cache-poisoning-prompt-injection)). Chained with 2026-015, one poisoned response becomes a cross-user prompt-injection channel.

### 2.4 Controls Shield implements (C1–C4)
A public red-team lab reproduced four attack scenarios (direct override, a 24,000-character buried payload, cross-caller cache leak, and post-approval drift) and defined four controls ([Mike Moore on DEV](https://dev.to/webofmike/mcp-prompt-injection-before-the-first-tool-call-2ol)):
- **C1 Isolate**: upstream instructions never enter the trusted prompt region; wrap and label them untrusted.
- **C2 Cap**: hard 4,096-character limit, the figure suggested in the advisory thread.
- **C3 Bind**: cache keys bind server identity and caller; never publicly cache a payload carrying `instructions`.
- **C4 Pin**: pin the instructions digest at first sight and reject drift, failing closed.

Shield implements all four, plus tool-definition pinning (rug pulls), tool-poisoning scans, step-level argument policy, egress/SSRF control, secret/PII redaction, output injection flagging, HITL approvals and a session kill switch. Your launch post can say, accurately: *"Shield blocks the MCP-2026-015 / 2026-008 chain today, before the spec fix lands."*

### 2.5 Full threat list (put in `docs/threat-model.md`)

| # | Threat | Where it enters | Shield control | Status |
|---|---|---|---|---|
| T1 | Server instructions injection (MCP-2026-015) | discovery | C1–C4 | done |
| T2 | Cross-caller cache poisoning (MCP-2026-008) | cache | identity-bound keys, refuse public+instructions, TTL cap | done |
| T3 | Tool poisoning (hidden text in descriptions/schemas) | tools/list | injection + hidden-unicode scan, quarantine | done |
| T4 | Rug pull (tool definition changes after approval) | tools/list | SHA-256 pin per tool, quarantine on drift | done |
| T5 | Indirect prompt injection via tool output | tools/call result | flag (warning wrapper) or block | done |
| T6 | Destructive actions (DROP, rm -rf, curl \| sh) | tools/call args | global + per-tool deny patterns, explicit tool deny | done |
| T7 | SSRF / cloud metadata access | tools/call args | private-network + scheme + domain egress policy | done (DNS rebinding in Sandbox) |
| T8 | Credential exfiltration through args | tools/call args | secret detection → deny | done |
| T9 | PII / secret leakage in results | tools/call result | redaction (Luhn-checked cards, SSN, keys, JWTs…) | done |
| T10 | Runaway loops | every step | max steps per session, rate limit | done |
| T11 | Privilege escalation via inherited human tokens | auth | scoped short-lived agent tokens, required scopes per tool | done (HS256); RFC 8693 in Phase 2 |
| T12 | Header/body smuggling ("authorize header, execute body") | transport | Mcp-Method / Mcp-Name must match body | done |
| T13 | Token passthrough to upstream | transport | agent token consumed at gateway; upstream uses its own credential | done |
| T14 | Sandbox escape | code execution | Firecracker microVMs | Phase 3 |

---

## 3. What you're building: Sentinel

One GitHub org / monorepo, four components that interoperate but can each be adopted alone:

| # | Component | Role | Phase |
|---|---|---|---|
| 1+2 | **Sentinel Shield** | MCP gateway/aggregator + step-level policy engine, in **one Go binary** | Phase 1 (launch artifact) |
| 4 | **Sentinel Identity** | Agent identity: RFC 8693 token exchange, scoped short-lived tokens, JWKS, revocation, audit | Phase 2 |
| 3 | **Sentinel Sandbox** | Ephemeral microVM code execution (Docker-hardened first, Firecracker next) | Phase 3 |
| — | **Sentinel Console** (optional) | Approvals inbox, audit search, pin re-approval UI | Phase 4 |

Why Gateway and Policy merge: the policy decision must happen **synchronously inside the request path**, for every step. A separate policy service adds a network hop to every tool call and a second thing to deploy. Shield embeds the evaluator in-process (and later embeds OPA's Go SDK the same way). Gateway and Policy stay separate **packages** (`internal/gateway`, `internal/policy`), so they can still be split later.

---

## 4. Architecture

### 4.1 System view

```
        Human user ──(OIDC login)──►  SENTINEL IDENTITY (Phase 2)
                                      - RFC 8693 token exchange: user token -> agent token
                                      - scope + TTL + session id (sid) + act.sub = agent
                                      - JWKS, revocation list (Redis), audit log
                                                │ short-lived agent JWT
                                                ▼
 ┌──────────────────────┐   MCP (Streamable HTTP, JSON-RPC 2.0)
 │ Agent host / client  │ ───────────────────────────────────────┐
 │ Claude Code, Cursor, │                                        │
 │ LangGraph, CrewAI    │                                        ▼
 └──────────────────────┘        ┌───────────────────────────────────────────────┐
                                 │            SENTINEL SHIELD  (Phase 1)          │
                                 │  1 authn: verify agent JWT, check revocation   │
                                 │  2 validate JSON-RPC + Mcp-Method/Mcp-Name     │
                                 │  3 discovery: own identity; upstream           │
                                 │    instructions capped/pinned/dropped|wrapped  │
                                 │  4 tools/list: aggregate, namespace, pin,      │
                                 │    quarantine, hide tools agent can't use      │
                                 │  5 tools/call: STEP POLICY                     │
                                 │    steps/rate -> allowlist -> scope ->         │
                                 │    deny patterns -> secrets -> egress -> HITL  │
                                 │  6 forward with backend's own credential       │
                                 │  7 results: redact PII/secrets, flag injection │
                                 │  8 telemetry event per step (-> OTel spans)    │
                                 │  identity-bound cache (server+caller keyed)    │
                                 └───────┬──────────────┬──────────────┬──────────┘
                                         │              │              │
                                   MCP server A    MCP server B   SENTINEL SANDBOX (Phase 3)
                                   (postgres)      (github,       exposed as an MCP server:
                                                    zoho, web)    sandbox__run_python, ...
                                                                  - pre-warmed microVM pool
                                                                  - no network unless policy allows
                                                                  - destroyed after task
        Admin API (separate port, admin token): approve/deny parked calls, revoke session (kill switch)
```

Request lifecycle: **Identity mints a scoped agent token → Shield authenticates and evaluates every step → approved calls go to the upstream MCP server, or to Sandbox for code execution → results are scanned on the way back → Identity revokes the session when the task ends or a human hits the kill switch.** This matches how WSO2 wires AI Gateway and Agent ID inside Agent Manager ([WSO2 architecture guide](https://wso2.com/api-platform/learn/agent-platform-architecture/)) and how Runlayer splits control plane (auth, policy, scanning, audit) from data plane (your MCP servers) ([Runlayer architecture](https://docs.runlayer.com/infrastructure/architecture)).

Key design choice: **Sandbox is just another MCP backend behind Shield.** Code-execution calls get the same policy, identity, audit and output scanning as every other tool, with no special path.

### 4.2 Interception pipeline → code map (already implemented)

| Stage | What happens | File |
|---|---|---|
| Auth | Bearer JWT verified (alg pinned to HS256, exp/nbf/iss/aud, `act.sub` = agent, `sid` required), revocation checked | `internal/identity/verifier.go` |
| Parse | Single JSON-RPC 2.0 message; batches rejected; 1 MiB body cap | `internal/mcp/jsonrpc.go` |
| Headers | `MCP-Protocol-Version` allowlist; `Mcp-Method`/`Mcp-Name` must match the body; strict mode requires them | `internal/gateway/gateway.go` `checkHeaders` |
| Discovery | Shield answers `initialize` / `server/discover` itself; upstream instructions go through C1/C2/C4 + injection scan; result marked `cacheScope: private` | `gateway.go` `handleDiscover`, `internal/guard/discovery.go` |
| tools/list | Fan out to backends (pagination), identity-bound cache, pin/quarantine, namespace `backend__tool`, hide tools the agent can't use | `gateway.go` `handleToolsList`, `internal/cache/cache.go` |
| tools/call policy | Step counter → rate limit → allowlist/explicit deny → required scope → deny regexes → secrets-in-args → egress/SSRF → HITL | `internal/policy/engine.go` `Evaluate` |
| Forward | Strip namespace, set routing headers, attach backend credential (never the agent's), circuit breaker, SSE or JSON responses, legacy session handshake | `internal/gateway/upstream.go` |
| Results | Redact configured data classes; scan for injection markers + hidden unicode; flag or block; add `_meta` decision | `gateway.go` `handleToolsCall`, `internal/guard/redact.go`, `injection.go` |
| Telemetry | One structured event per step (agent, subject, session, backend, tool, decision, rule, reason, latency, findings) | `internal/telemetry/telemetry.go` |
| Human controls | `GET /admin/approvals`, `POST /admin/approvals/{id}/approve\|deny`, `POST /admin/revoke` | `internal/gateway/admin.go`, `internal/hitl/hitl.go` |

### 4.3 Decision semantics (important for agent UX)
- Policy denials and pending approvals return a **normal `CallToolResult` with `isError: true`** and a human-readable reason, not a JSON-RPC protocol error. The model sees why it was blocked and can explain it to the user instead of retrying blindly. Every result carries `_meta["dev.sentinel/decision"]` and `_meta["dev.sentinel/rule"]`.
- Protocol problems (bad JSON, header mismatch, unknown method) return JSON-RPC errors. Auth failures return HTTP 401 with `WWW-Authenticate`.
- Forbidden tools are **hidden from `tools/list`**, so the model doesn't plan around them. They are also blocked on call, in case the model guesses the name.
- Approvals are bound to a fingerprint of `(session, tool, canonical args)`. Changing one character of the arguments needs a new approval, and each approval is single-use.
- Every attempt counts toward `max_steps_per_session`, including denied ones. Otherwise a hijacked agent could loop on denials forever.

### 4.4 policy.yaml reference (v1 schema)

```yaml
version: "1"
default_action: deny                 # unlisted tools are hidden + blocked
global:
  deny_arg_patterns: ['(?i)\b(?:drop|truncate|alter)\s+(?:table|database|schema)\b', '(?i)\bdelete\s+from\b']
  block_secrets_in_arguments: true   # AWS/GitHub/OpenAI/Anthropic/Slack keys, JWTs, private keys
  mask_in_results: [credit_card, ssn, aws_access_key, github_token, private_key, jwt, openai_key, anthropic_key, slack_token, generic_api_key]
  mask_in_arguments: []              # also: email, phone
  egress:
    block_private_networks: true     # loopback, RFC1918, link-local (169.254/16), *.internal, metadata hosts
    deny_domains: ["pastebin.com", "*.ngrok.io", "webhook.site"]
  discovery:
    upstream_instructions: drop      # drop | wrap
    max_instruction_chars: 4096
    pin_instructions: true
    pin_tool_definitions: true
    block_poisoned_tools: true
  output_scanning:
    on_injection: flag               # flag | block | off
agents:
  - id: customer-support-bot         # matches act.sub in the agent token; "*" = fallback
    max_steps_per_session: 25
    rate_limit_per_minute: 60
    egress: { allow_domains: ["docs.example.com", "*.zoho.com"] }
    tools:
      - { name: postgres__query, require_scope: "db:read", deny_arg_patterns: ['(?i)\b(?:insert|update|grant)\b'] }
      - { name: postgres__execute, deny: true }
      - { name: slack__send_message, require_approval: true }
      - { name: "github__*" }        # globs allowed; explicit deny rules always win
```

Hot reload: `kill -HUP <pid>`. An invalid file is rejected and the previous policy stays active.

### 4.5 Path to OPA/Rego (Phase 1b)
Keep YAML as the default authoring format. Compile it into a Rego bundle, or let advanced users write Rego directly, and evaluate with OPA's Go SDK in-process. The input document is exactly what `Evaluate` already receives: `{principal:{sub,agent_id,sid,scopes}, tool, arguments, counters:{steps,rate}}`. The existing table-driven tests become the conformance suite: YAML and Rego must produce identical decisions.

---

## 5. Component deep dives

### 5.1 Sentinel Shield (Phase 1, built)
Covered in section 4. Remaining Phase 1 work is in section 9.1.

### 5.2 Sentinel Identity (Phase 2)
**Problem:** agents inherit a human's static API key or OAuth token, which is a security and audit nightmare. WSO2 Agent Manager and Runlayer both treat agents as first-class identities with delegation and instant revocation ([WSO2 Agent Manager](https://wso2.com/agent-platform/agent-manager/)).

**Design:**
- **Token endpoint implementing RFC 8693** (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`): `subject_token` = the human's OIDC token (from Keycloak, Auth0, Zoho, Google), `actor_token` = the agent's registered credential. The output is a JWT with `sub` = human, `act.sub` = agent, `sid` = new session, `scope` = intersection of what the human has, what the agent is registered for, and what was requested. `exp` is 5–15 minutes. Shield already reads exactly these claims.
- **ES256 signing + JWKS** at `/.well-known/jwks.json` with key rotation. Shield gets a `JWKSVerifier` that implements the existing `identity.Verifier` interface, so there are no gateway changes.
- **Agent registry**: agent id, owner, allowed scopes, allowed backends, environment (dev/staging/prod).
- **Revocation**: Redis set of revoked `sid`s with TTL = max token lifetime. Shield implements `identity.Revocations` against the same Redis. `POST /revoke {session_id}` is the kill switch. Auto-revoke when the agent host signals task completion.
- **SPIFFE-style workload identity** between Sentinel's own services: mTLS with short-lived X.509-SVIDs (`spiffe://sentinel.local/shield`, `/sandbox`, `/identity`). Start with a small internal CA; adopt SPIRE when deploying on Kubernetes.
- **Audit log** (Postgres, append-only): issuance, exchange, revocation, and every Shield decision, joined on `sid`. This is the SOC 2-style agent audit trail.
- **MCP authorization spec compatibility**: expose OAuth protected-resource metadata on Shield so standard MCP clients can discover the authorization server, and never pass a client's token through to upstreams. Shield already enforces the second rule.

### 5.3 Sentinel Sandbox (Phase 3)
**Problem:** teams want "give the agent a computer" without trusting the agent's code. Containers share the host kernel; microVMs don't.

**Design:**
- **Exposed as an MCP server** behind Shield: `sandbox__run_python`, `sandbox__run_bash`, `sandbox__read_file`, `sandbox__write_file`. Policy, identity and audit come free.
- **Phase 3a — hardened Docker driver** (runs anywhere, including CI and macOS for contributors): `--network none`, `--read-only`, tmpfs workdir, `--cap-drop ALL`, `--security-opt no-new-privileges`, a seccomp profile, cgroup v2 CPU/memory/pids limits, wall-clock timeout, and gVisor (`runsc`) when available.
- **Phase 3b — Firecracker driver** (Linux + KVM): control plane API → per-node orchestrator daemon → microVMs restored from a snapshot, with a **pre-warmed pool** to hide boot latency. A guest agent (small Go binary) talks over vsock, executes code, and streams stdout/stderr/exit code/artifacts. The VM is destroyed after the task, or reset from snapshot and returned to the pool. Firecracker's `jailer` provides chroot + seccomp + cgroups around each VMM.
- **Egress**: none by default. If policy allows domains, route through an egress proxy that resolves DNS once and pins the IP. This closes the DNS-rebinding gap noted in Shield's egress check.
- **Driver interface**: `Create(limits) → Exec(code, stream) → Destroy()`. Both drivers must pass the same test suite, which runs known escape attempts (fork bombs, `/proc` probes, metadata IP, raw sockets, writing outside the workdir).
- **Outputs** go back through Shield, so secrets printed by code are redacted like any other tool result.

---

## 6. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Shield, Identity, Sandbox control plane | **Go 1.22+** (stdlib `net/http`, `log/slog`; one dependency so far: `gopkg.in/yaml.v3`) | Single static binary, low latency, what infra buyers expect |
| Policy | YAML v1 → **OPA (embedded Go SDK)** in Phase 1b | Policy-as-code, testable, transfers to K8s admission control |
| Custom guardrails / ML detectors | **Python plugin SDK** (FastAPI or gRPC sidecar): Presidio for PII, small classifier for injection | Use the Python ML ecosystem, isolated off the hot path, with a timeout and fail-closed by policy choice |
| Protocol | **MCP 2026-07-28** (stateless, routing headers) + legacy 2025-06-18 / 2025-11-25 upstreams | Clients and servers will be mixed for a while |
| Identity | RFC 8693, JWT ES256 + JWKS, SPIFFE-style mTLS internally | Standards, interoperable with existing IdPs |
| Tracing | `telemetry.Recorder` → **OpenTelemetry** spans (one per step) → Jaeger / Tempo / Grafana | Matches WSO2's OTel-native story |
| Storage | **Redis** (revocations, counters, rate limits, approvals), **Postgres** (audit, pins, agent registry, policy versions) | In-memory implementations exist behind interfaces today |
| Sandbox | Hardened Docker / gVisor → **Firecracker** | Real hardware isolation, low contributor barrier |
| Packaging | Docker Compose (dev), Helm chart (prod), goreleaser binaries | Five-minute start, enterprise-credible prod path |
| License | **Apache 2.0** | Same as WSO2 Agent Manager; avoids the AGPL hesitation Archestra faces |

---

## 7. Repository

### 7.1 Layout (monorepo, Go workspace)

```
sentinel/
├── go.work                          # use ./shield ./identity ./sandbox
├── LICENSE                          # Apache-2.0
├── README.md                        # threat-first positioning + 30-second GIF of the demo
├── docs/
│   ├── BRIEF.md                     # this file
│   ├── threat-model.md              # table 2.5, expanded
│   ├── policy-reference.md          # section 4.4, expanded
│   └── adr/                         # 0001-merge-gateway-and-policy.md, 0002-tool-errors-as-results.md, ...
├── shield/                          # Phase 1 — BUILT (see 7.2)
├── identity/                        # Phase 2
│   ├── cmd/identity/
│   ├── internal/tokenexchange/      # RFC 8693
│   ├── internal/jwks/
│   ├── internal/registry/
│   └── internal/revocation/         # Redis
├── sandbox/                         # Phase 3
│   ├── cmd/sandbox-mcp/             # MCP server facade (sandbox__run_python ...)
│   ├── internal/driver/docker/
│   ├── internal/driver/firecracker/
│   ├── orchestrator/                # per-node pool daemon
│   ├── guest-agent/                 # vsock exec agent inside the VM
│   └── images/                      # rootfs + kernel build scripts
├── plugins-sdk-python/              # sentinel-guard: custom detectors over gRPC
├── examples/
│   ├── claude-code/                 # .mcp.json pointing at Shield
│   ├── cursor/
│   ├── langgraph/
│   └── zoho-crm-mcp-server/         # your CRM background: scoped, auto-expiring CRM updates
└── deploy/
    ├── docker-compose.yaml          # shield + identity + redis + postgres + jaeger
    └── helm/
```

### 7.2 What already exists in `shield/` (tested)

```
shield/
├── cmd/shield/main.go               # server, -mint dev tokens, SIGHUP reload, graceful shutdown
├── cmd/demo-upstream/main.go        # fake postgres + malicious web MCP servers for the demo
├── configs/shield.yaml              # listen, admin, auth, backends (stateless + legacy)
├── configs/policy.yaml              # example policy (three agent profiles)
├── examples/exploit-demo/demo.sh    # attack without Shield, then with Shield, then kill switch
└── internal/
    ├── mcp/        jsonrpc.go       # JSON-RPC types, ToolErrorResult, Sentinel error codes
    ├── identity/   verifier.go      # Verifier + Revocations interfaces, HS256 impl, SignHS256
    ├── policy/     policy.go engine.go engine_test.go
    ├── guard/      redact.go injection.go discovery.go guard_test.go
    ├── cache/      cache.go cache_test.go
    ├── hitl/       hitl.go          # fingerprinted, single-use approvals
    ├── telemetry/  telemetry.go     # Recorder interface, slog + memory impls
    └── gateway/    gateway.go upstream.go admin.go gateway_test.go e2e_test.go
```

Verified status: `go vet` clean, `go test -race ./...` passes 38 test cases. The demo script runs every attack against the raw servers (all succeed) and then through Shield (all blocked, legitimate read allowed with PII redacted, revoked session rejected).

Quick start:
```bash
cd shield
export SENTINEL_HS256_SECRET="dev-secret-change-me-dev-secret-change-me"
export SENTINEL_ADMIN_TOKEN="dev-admin-token"
go test -race ./...
./examples/exploit-demo/demo.sh
```

Point Claude Code at it (dev):
```json
{ "mcpServers": { "sentinel": { "type": "http", "url": "http://localhost:8080/mcp",
    "headers": { "Authorization": "Bearer <output of: go run ./cmd/shield -mint -agent customer-support-bot -scope db:read>" } } } }
```

### 7.3 Security invariants (the coding agent must never break these)
Invariants 1–11 each have a test; #12 is enforced in `cmd/shield` (adding its test is part of Phase 1). A change that breaks any of them needs an ADR and a human sign-off.
1. The agent's bearer token is **never forwarded** upstream.
2. Cache keys **always** include verified server identity (config name, not self-reported `serverInfo`) **and** caller identity. `cacheScope: public` never shares across callers.
3. A payload with `instructions` and `cacheScope: public` is **never stored**.
4. Upstream `instructions` never reach the model as trusted text: they are dropped, or wrapped, capped and pinned.
5. Tool definition drift **quarantines** the tool (fail closed) until a human re-approves it.
6. `Mcp-Method` / `Mcp-Name` headers that disagree with the body are **rejected**.
7. `default_action: deny` hides **and** blocks unlisted tools.
8. Explicit `deny: true` rules win over any allow glob.
9. Approvals are bound to `(session, tool, canonical args)` and are **single-use**.
10. Every tool-call attempt counts toward `max_steps_per_session`.
11. A revoked `sid` is rejected on the **next request**, with no caching of auth decisions.
12. A policy reload that fails validation **keeps the previous policy**.

---

## 8. Build order (Shield-first)

| Phase | Weeks | Ship | Demo / launch moment |
|---|---|---|---|
| **1 — Shield core** | 1–4 | Section 9.1 backlog on top of the existing code: OTel, Redis counters, persistent pins + re-approval CLI, resources/prompts proxying, stdio backends, Docker image | Tag `shield v0.1.0`. Post on LinkedIn: "I reproduced MCP-2026-015 + 2026-008 and built a gateway that blocks it" with the demo GIF |
| **1b — Policy-as-code** | 5–6 | Embedded OPA, YAML→Rego compiler, Python plugin SDK (Presidio PII, injection classifier), `shield policy test` CLI | Blog: "Step-level policy for agent loops: why prompt-and-response firewalls miss the middle 48 steps" |
| **2 — Identity** | 7–9 | RFC 8693 token exchange, ES256/JWKS, agent registry, Redis revocation, audit log, Shield `JWKSVerifier` | **Hacker News launch** of Shield + Identity: "Show HN: Open-source zero-trust gateway for MCP agents (blocks MCP-2026-015 today)" |
| **3 — Sandbox** | 10–16 | 3a hardened Docker driver (wk 10–12) → 3b Firecracker driver, warm pool, vsock agent (wk 13–16) | "Devin-style sandbox behind the same policy engine": run the escape-attempt suite live |
| **4 — Fabric** | 17+ | docker-compose all-in-one, Helm chart, Console UI, comparison docs, Zoho CRM example | Portfolio case study + talk proposal (local meetups, WSO2Con-style conference CFPs) |

Rule: every phase ends with a tagged release, a README quickstart and a recorded demo. Never have four half-built services at once.

---

## 9. Backlog for the coding agent

### 9.1 Phase 1 (Shield core), in order
1. **OpenTelemetry recorder**: implement `telemetry.Recorder` with `go.opentelemetry.io/otel`. One span per step named `mcp.<method>`, with attributes `sentinel.agent_id`, `sentinel.tool`, `sentinel.decision`, `sentinel.rule`, `sentinel.backend`, plus latency. Propagate `traceparent` from the client and to upstreams. Add Jaeger to docker-compose.
2. **Redis-backed state**: interfaces for `Counters`, `hitl.Store`, `identity.Revocations` and `guard.PinStore`, with Redis implementations. Keep the memory versions for tests. Multi-replica correctness test.
3. **Persistent pins + re-approval**: Postgres `PinStore`, plus `shield pins list|diff|approve <server> <tool>` CLI that shows the definition diff before re-approval.
4. **Proxy `resources/*` and `prompts/*`** with the same namespace, policy (`resources/read` URIs go through the egress check) and output scanning. Add `prompts/get` text to injection scanning.
5. **stdio backends**: launch local MCP servers as child processes (like Lasso's `mcp.json` model), with env allowlisting and restart policy.
6. **Server→client streaming**: relay progress notifications and, behind policy, sampling/elicitation requests over SSE.
7. **Policy features**: per-tool argument JSON-schema constraints, time-of-day/environment conditions, a `dry_run: true` mode that logs decisions without enforcing (critical for adoption).
8. **Approvals UX**: Slack/webhook notifier for pending approvals, with approve/deny links signed with short-lived HMAC.
9. **Packaging**: multi-stage Dockerfile (distroless), goreleaser, `docker run` quickstart, `examples/claude-code` and `examples/cursor`.
10. **Benchmarks**: `go test -bench` for the full pipeline. Target < 2 ms p99 added latency for an allowed `tools/call` (excluding upstream). Publish the numbers in the README.

### 9.2 Known limitations to document honestly
- Regex-based injection detection is a heuristic first line, not a guarantee. The Python plugin SDK adds a classifier, and deterministic controls (allowlists, scopes, egress, approvals) are the real boundary.
- Egress checks inspect URLs and IP literals in arguments. They do not resolve DNS (Sandbox egress proxy closes this).
- Pins are first-sight (trust on first use). Pre-approve pins from a registry for stronger guarantees.
- v0.1 handles POST JSON-RPC only (no standalone GET SSE stream) and supports `tools/*`, discovery and `ping`.

---

## 10. Skills checklist (priority order)

| # | Skill | Needed for | Starting point |
|---|---|---|---|
| 1 | Go: `net/http`, context, goroutines, interfaces, table-driven tests, `-race` | Everything | Read `shield/internal/gateway` top to bottom, then *Learn Go with Tests* |
| 2 | MCP spec (2026-07-28 + 2025-06-18), JSON-RPC 2.0 | Shield | modelcontextprotocol.io specification + the [APS-2026-01 advisory](https://github.com/Moai-Team-LLC/agentic-product-standard/blob/main/docs/advisories/APS-2026-01-mcp-2026-07-28.md) |
| 3 | Agent attack techniques: tool poisoning, rug pulls, indirect injection, cache poisoning | Threat model, demo | [mcp-redteam-lab](https://github.com/themsquared/mcp-redteam-lab), [Datapace write-up](https://datapace.ai/blog/mcp-cache-poisoning-prompt-injection) |
| 4 | OpenTelemetry (Go) | Phase 1 | OTel Go getting-started, then add spans to `handleToolsCall` |
| 5 | Redis data structures (INCR/EXPIRE, sets, Lua for atomic windows) | Phase 1 | Counters + revocation implementations |
| 6 | OPA / Rego | Phase 1b | OPA playground; port `TestStepDecisions` to Rego |
| 7 | OAuth 2.0 / OIDC internals, RFC 8693, JWS/JWK (ES256) | Phase 2 | Implement the token endpoint against a local Keycloak |
| 8 | X.509 / mTLS, SPIFFE concepts | Phase 2 | Small internal CA with `crypto/x509` |
| 9 | Linux isolation: namespaces, cgroups v2, seccomp, capabilities | Phase 3a | Harden a Docker run by hand, then automate it |
| 10 | KVM, Firecracker API + jailer, vsock, snapshots | Phase 3b | Firecracker getting-started, then the snapshot docs |
| 11 | gRPC | Plugin SDK, sandbox orchestrator | Protobuf contract for `Detect(text) → findings` |

Given your C#/JS background, Go syntax will come quickly (Go interfaces are like C# interfaces, but satisfied implicitly). The real learning curve is items 7 and 9–10. Budget the most time there.

---

## 11. Launch & positioning playbook

- **Lead with the exploit, not the features.** The demo script already produces the story: (1) the poisoned server's instructions and an injected web page, (2) the hijacked agent dropping a table, (3) the same chain through Shield: instructions withheld, injection flagged, `DROP` denied, exfiltration denied, SSRF denied, legitimate read allowed with PII redacted, (4) the kill switch. Record it as a 60-second terminal GIF, and also with a real agent in Claude Code.
- **Cite the real issue IDs** (MCP-2026-015, MCP-2026-008) and link the public write-ups. That is instant credibility on HN. Be precise: these are spec issue IDs, not CVEs ([RuntimeWire](https://runtimewire.com/article/mcp-prompt-injection-before-first-tool-call)).
- **Comparison table** in the README against WSO2 Agent Manager, Archestra, Lasso and Runlayer (section 1.3). Be fair, and win on "single binary, Apache 2.0, step-level policy + identity + sandbox, five-minute start".
- **Integrations people already use**: Claude Code, Cursor, LangGraph, CrewAI examples on day one.
- **The Zoho CRM example** is your portfolio differentiator: "an agent that can update a CRM record only with a 10-minute scoped token, after a human approves the exact change, with a full audit trail."
- **Release cadence**: a tagged release and a short write-up every phase. That gives you four launches instead of one.

---

## 12. Working rules for the AI coding agent
- Read this file and the code before proposing changes. Work in small PRs, one backlog item each.
- Tests first for any security-relevant behavior. Never weaken a test in 7.3 to make a change pass.
- Keep dependencies minimal. Justify every new module in the PR description.
- Fail closed: if a guard, plugin or upstream errors, deny with a clear reason. Never allow silently.
- No secrets in code or configs. Use `${ENV}` expansion only.
- Every new decision path emits a telemetry event with a stable `rule` id.
- Update `docs/threat-model.md` and `docs/policy-reference.md` in the same PR as the code.
