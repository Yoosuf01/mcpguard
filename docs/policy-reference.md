# policy.yaml reference (schema v1)

Derived from `shield/internal/policy/policy.go` (the code is authoritative). `${ENV}` references are
expanded at load. Hot reload with `kill -HUP <pid>`; an invalid file is rejected and the previous policy stays active.

```yaml
version: "1"                  # required; only "1" is accepted
default_action: deny          # deny (default) | allow. Unlisted tools are hidden AND blocked when deny.
dry_run: false                # true: evaluate and log policy decisions (dry_run_deny/dry_run_pending) without blocking
global:
  deny_arg_patterns: []       # regexes matched against every string (keys + values) in tool arguments
  block_secrets_in_arguments: true   # AWS/GitHub/OpenAI/Anthropic/Slack keys, JWTs, private keys => deny
  mask_in_results: []         # kinds: credit_card ssn aws_access_key github_token private_key jwt
                              #        openai_key anthropic_key slack_token generic_api_key email phone
  mask_in_arguments: []       # same kinds; masked before forwarding upstream
  egress:
    block_private_networks: true   # default true: loopback, RFC1918, link-local, *.internal, *.local, metadata hosts
    allow_domains: []         # if non-empty, only these (globs like *.zoho.com) may appear in URLs
    deny_domains: []
  discovery:
    upstream_instructions: drop    # drop | wrap
    max_instruction_chars: 4096
    pin_instructions: true
    pin_tool_definitions: true
    block_poisoned_tools: true
  output_scanning:
    on_injection: flag             # flag (default) | block | off
agents:
  - id: customer-support-bot       # matches act.sub in the agent token; "*" is the fallback
    dry_run: false                 # optional per-agent override for dry_run mode
    max_steps_per_session: 25      # every attempt counts (see threat-model G1)
    rate_limit_per_minute: 60
    egress: { allow_domains: ["docs.example.com"] }   # merged over global egress
    tools:
      - { name: postgres__query, require_scope: "db:read", deny_arg_patterns: ['(?i)\b(?:insert|update)\b'] }
      - { name: postgres__execute, deny: true }       # explicit deny always wins over a glob
      - { name: slack__send_message, require_approval: true }
      - { name: "github__*" }                         # glob allowed
```

## Evaluation order (`policy.Engine.Evaluate`)
1. Step counter, then rate limit (every attempt counts)
2. Allowlist / explicit deny / required scope
3. Deny regexes (global + per tool), then secrets-in-arguments, then egress
4. Human approval (last, so a human is never asked to approve what policy would deny)

## Decision semantics
- Denials and pending approvals return a normal `CallToolResult` with `isError: true` and a reason, plus `_meta["dev.mcpguard/decision"]` and `_meta["dev.mcpguard/rule"]`.
- Protocol problems return JSON-RPC errors; auth failures return HTTP 401 with `WWW-Authenticate`.
- Approvals bind to `(session, tool, canonical args)` and are single-use.

## Policy-as-Code: Embedded OPA / Rego Engine & Compiler (Phase 1b)

MCPGuard includes an embedded Open Policy Agent (OPA) engine running native Rego v1, alongside the native Go evaluator.

### 1. Compile Declarative YAML to Native Rego
```bash
mcpguard policy compile configs/policy.yaml -o configs/policy.rego
```
The compiler transforms declarative YAML profiles into deterministic Rego rules (`package mcpguard.policy`) evaluating against the standard step input document:
- `input.principal`: `{subject, agent_id, session_id, scopes}`
- `input.tool`: tool name (e.g., `postgres__query`)
- `input.arguments`: tool arguments object
- `input.counters`: `{steps, rate}`

### 2. Testing Policies with Fixtures CLI
```bash
# Test YAML or Rego policy against test fixture assertions
mcpguard policy test configs/policy.yaml configs/policy_test.json
mcpguard policy test configs/policy.rego configs/policy_test.json
```
The test command evaluates each fixture assertion, displaying execution duration, action, and rule matches:
```
=== Evaluating Policy: configs/policy.yaml (17 test cases) ===
✓ PASS [0.60ms] read query allowed (allow / allow)
✓ PASS [0.11ms] DROP TABLE blocked (deny / deny_arg_pattern)
...
Results: 17 passed, 0 failed in 2.53ms
```

### 3. Conformance Suite
The conformance test suite (`shield/internal/policy/conformance_test.go`) evaluates all security invariants across both the Go engine and the Rego engine, proving 100% parity across:
- Runaway breaker step counters (`max_steps_per_session`)
- Tool namespace allowlisting & explicit denies (`tool_denied`, `tool_not_allowed`)
- Scoped token verification (`missing_scope`)
- Deny argument regex patterns (`deny_arg_pattern`)
- Credential exfiltration prevention (`secret_in_arguments`)
- SSRF and domain egress controls (`egress_private_network`, `egress_deny_domain`, `egress_not_allowlisted`, `egress_scheme`)
- Human approval requirements (`require_approval`)
- Simulation mode (`dry_run: true`)

## Sentinel Identity & Enterprise Auth (Phase 2)

Shield supports both standalone HMAC (HS256) for local development and distributed enterprise identity with ECDSA P-256 (`ES256`) and JWKS discovery (`JWKSVerifier`).

### Verifier Configuration (`internal/identity`)

```go
verifier := identity.NewJWKSVerifier(identity.JWKSVerifierOptions{
    JWKSURL:            "https://identity.sentinel.local/.well-known/jwks.json",
    Issuer:             "https://identity.sentinel.local",
    Audience:           "mcpguard-shield",
    Revocations:        redisRevocations,
    RefreshInterval:    15 * time.Minute,
    MinRefreshCooldown: 5 * time.Second,
})
```

### Claims Schema
Delegated agent tokens carry standard OIDC claims plus RFC 8693 token exchange actor claims:
- `sub`: Human user or initiating principal (e.g., `alice@example.com`).
- `act.sub`: Delegated agent identifier (e.g., `customer-support-bot`). Shield also accepts `agent_id` for backwards compatibility.
- `sid`: Unique agent session ID (e.g., `sess_123456`). Bound to step counters, single-use approvals, and instant revocation.
- `scope`: Space-delimited granted scopes (e.g., `"db:read crm:update"`).
- `exp` / `nbf`: Standard expiration and not-before timestamps. Expired tokens are rejected (`ErrExpired`).

### RFC 8693 Token Exchange Endpoint (`internal/identity`)

Sentinel Identity provides an RFC 8693 token exchange engine (`TokenExchangeEngine`) and HTTP handler (`POST /oauth/token`):

```bash
curl -X POST https://identity.sentinel.local/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${HUMAN_OIDC_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "actor_token=${AGENT_CREDENTIAL}" \
  -d "actor_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "scope=db:read"
```

#### Scope Intersection Math
Granted scopes are strictly computed as:
$$\text{Granted} = \text{Human} \cap \text{Agent} \cap \text{Requested}$$
If requested scopes are omitted, all scopes in $\text{Human} \cap \text{Agent}$ are granted. If an agent requests a scope not held by the human, or if the intersection is disjoint, the exchange is rejected with standard OAuth `400 invalid_scope`.

### Agent Identity Registry (`internal/identity`)

The Agent Identity Registry manages the registration, lifecycles, and capabilities of AI agents:

```go
type AgentProfile struct {
    ID              string      `json:"id"`               // Agent ID (e.g. "customer-support-bot")
    Name            string      `json:"name"`             // Descriptive name
    Owner           string      `json:"owner"`            // Owner team/email
    AllowedScopes   []string    `json:"allowed_scopes"`   // Scope boundary caps
    AllowedBackends []string    `json:"allowed_backends"` // Permitted MCP backends
    Environment     string      `json:"environment"`      // "dev" | "staging" | "prod"
    Status          AgentStatus `json:"status"`           // "active" | "suspended" | "revoked"
}
```

Available registry implementations:
- `MemoryAgentRegistry`: In-memory thread-safe adapter for standalone Shield gateways and unit testing.
- `RedisAgentRegistry`: Distributed multi-replica adapter backed by Redis key-value and set indexing (`mcpguard:agent:profile:<id>` and `mcpguard:agents:set`).

### OAuth 2.0 Protected Resource Metadata (RFC 9470)

Shield exposes OAuth 2.0 Protected Resource Metadata under `/.well-known/oauth-protected-resource` so agents, SDKs, and clients can dynamically discover authorization server endpoints and supported scopes without manual configuration:

```bash
curl -i https://gateway.sentinel.local/.well-known/oauth-protected-resource
```
Response:
```json
{
  "resource": "https://gateway.sentinel.local",
  "authorization_servers": [
    "https://auth.sentinel.local"
  ],
  "scopes_supported": [
    "db:read",
    "db:write",
    "web:fetch"
  ],
  "bearer_methods_supported": [
    "header"
  ],
  "resource_documentation": "https://docs.mcpguard.dev"
}
```

Configured in `shield.yaml` under `auth`:
```yaml
auth:
  jwks_url: "https://auth.sentinel.local/.well-known/jwks.json"
  resource_url: "https://gateway.sentinel.local"
  auth_servers:
    - "https://auth.sentinel.local"
  scopes_supported:
    - "db:read"
    - "db:write"
    - "web:fetch"
```

### Distributed Real-Time Session Revocation (Redis Pub/Sub)

Shield implements instant sub-millisecond distributed session revocation push across all gateway replicas using Redis Pub/Sub combined with an in-memory fast path lookup table (`PubSubRedisRevocations`):

```go
revs, err := state.NewPubSubRedisRevocations(state.PubSubRevocationsOptions{
    Client:  redisClient,
    TTL:     7 * 24 * time.Hour,
    Channel: state.DefaultRevocationChannel, // "mcpguard:revocations:channel"
})
```

- **Zero-Latency In-Memory Fast-Path**: Incoming requests check the local memory table first (0 ms added latency).
- **Sub-Millisecond Distributed Push**: When `Revoke(ctx, sid)` is triggered anywhere (e.g. admin API or threat detector), the revocation is persisted to Redis and broadcast over the Pub/Sub channel. All gateway replicas update their local tables immediately.
- **Fail-Safe Fallback**: If a replica was disconnected or recently booted, cache misses query Redis directly (`EXISTS mcpguard:revoked:<sid>`) and backfill the local table.

## Sentinel Sandbox (Phase 3)

The Sentinel Sandbox provides isolated, unprivileged compute environments for agents to execute bash, python, and file operations safely.

### Sandbox Driver Interface (`internal/sandbox`)

All sandbox isolation runtimes (hardened Docker, gVisor, Firecracker microVMs) implement the `Driver` and `Instance` interfaces:

```go
type Limits struct {
    CPUs         float64       // CPU allocation (e.g. 1.0)
    MemoryBytes  int64         // Memory limit (e.g. 256MB)
    MaxProcesses int64         // Pids cgroup limit (e.g. 64) to prevent fork bombs
    Timeout      time.Duration // Wall-clock execution timeout
    WorkdirBytes int64         // Ephemeral workspace tmpfs quota
}

type Instance interface {
    ID() string
    Exec(ctx context.Context, opts ExecOptions) (*ExecResult, error)
    ReadFile(ctx context.Context, path string) ([]byte, error)
    WriteFile(ctx context.Context, path string, data []byte) error
    Destroy(ctx context.Context) error
}
```

### Shared Escape-Attempt Conformance Suite

Every driver must pass the unified isolation verification suite (`RunDriverConformanceSuite` in `internal/sandbox/suite_test.go`):
1. **Fork Bomb Defeat**: `:(){ :|:& };:` contained and aborted via process limits (`ErrProcessLimit`).
2. **Read-Only Root Filesystem**: Writes outside `/workspace` rejected with `ErrReadOnlyFS`.
3. **No-Network Namespace**: External connections and cloud metadata calls (`169.254.169.254`) blocked (`ErrNetworkBlocked`).
4. **Wall-Clock Hard Timeout**: Commands exceeding deadline terminated cleanly (`ErrTimeout`).
5. **Workspace Confinement**: Read/write isolated to ephemeral workspace with clean disposal on `Destroy()`.

### Hardened Docker Driver (`internal/sandbox/docker.go`)

The Docker driver executes agent commands inside ephemeral, unprivileged Linux containers with multi-layered kernel defense:
- `--network none`: Drops all network stack interfaces, stopping egress and metadata SSRF at the socket layer.
- `--read-only`: Enforces an immutable root filesystem (`/`, `/etc`, `/usr`, `/bin`).
- `--tmpfs /workspace:rw,size=<limit>`: All writeable state is isolated in memory and discarded upon destruction.
- `--cap-drop ALL`: Strips all Linux capabilities; blocks raw sockets, device access, and privilege escalation.
- `--security-opt no-new-privileges`: Precludes privilege gain via `setuid` binaries.
- `--pids-limit <limit>`: Cgroups process cap preventing fork bombs and thread exhaustion.
- `--memory` / `--cpus`: Cgroups v2 resource quotas.

### Sandbox MCP Server Backend (`internal/sandbox/server.go`)

The Sandbox MCP server exposes isolated compute capabilities directly as standard MCP tools behind the Shield gateway:
- `sandbox__run_bash`: Execute shell commands inside the unprivileged container workspace.
- `sandbox__run_python`: Execute Python 3 scripts within the sandbox.
- `sandbox__read_file`: Read files from the ephemeral tmpfs `/workspace`.
- `sandbox__write_file`: Write source code or inputs into `/workspace`.
- `sandbox__reset_session`: Tear down the container instance and wipe its workspace.

```yaml
# In shield.yaml
backends:
  - name: sandbox
    url: "http://127.0.0.1:9005"
```

All sandbox tools automatically inherit Shield step limits, token delegation, approval workflows, and output PII/secret redaction.

### DNS-Pinned Forward Egress Proxy (`internal/sandbox/proxy.go`)

The DNS-pinned egress proxy provides secure outbound network access for sandboxes when internet access is permitted by policy:
- **One-Shot DNS Resolution**: Resolves hostnames exactly once upon request initiation.
- **SSRF & Private Network Defense**: Evaluates resolved IPs against private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`) and cloud metadata endpoints (`169.254.169.254`), returning `403 Forbidden` on violations.
- **Socket IP Pinning**: Dials the verified IP address directly (`ip:port`), with dialer `Control` validation preventing DNS rebinding (TOCTOU) attacks.
- **HTTPS Tunneling**: Supports `CONNECT` method for encrypted HTTPS communication with target verification.

### Firecracker MicroVM Driver (`internal/sandbox/firecracker.go`)

Provides true hardware-assisted hardware virtualization isolation via Linux KVM:
- **Guest Kernel Isolation**: Untrusted agent code runs in a dedicated Linux guest kernel, completely isolated from the host.
- **AF_VSOCK Guest Agent Communication**: High-speed, point-to-point host-to-guest framing protocol over virtio-vsock.
- **Pre-Warmed Pool**: Pre-boots microVMs to eliminate cold-start boot latency, achieving $< 5\text{ ms}$ task acquisition.
- **Unified Conformance**: Conforms to the exact same escape-attempt test suite (`RunDriverConformanceSuite`) as the container runtimes.

---

## Production Deployment: Kubernetes Helm Chart & Docker Compose (Phase 4)

### Production Kubernetes Helm Chart (`deploy/helm/mcpguard`)

The MCPGuard Helm chart deploys a zero-trust, highly available gateway cluster on Kubernetes:
- **Restricted Pod Security Standard**: Enforces `runAsNonRoot: true`, `runAsUser: 65532`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, and `capabilities: drop: ["ALL"]`.
- **Zero-Trust NetworkPolicy**: Limits ingress to MCP port `8080`, restricts Admin/Metrics port `8081` to monitoring namespaces, and enforces egress restrictions with link-local cloud metadata (`169.254.169.254/32`) explicitly blocked.
- **High Availability**: Configured with `minReplicas: 2`, `PodDisruptionBudget` (`minAvailable: 1`), and `podAntiAffinity` across nodes.
- **Config & Secret Separation**: `shield.yaml` and `policy.yaml` mounted via versioned ConfigMaps with automatic rolling upgrade checksums; sensitive tokens (`SHIELD_ADMIN_TOKEN`, `SHIELD_AUTH_HS256_SECRET`) injected via Kubernetes Secrets or external secret stores.

### Production Docker Compose Stack (`deploy/docker-compose.yaml`)

Provides a unified single-command deployment stack featuring:
- **MCPGuard Gateway** with distroless container execution and `-version` container healthchecks.
- **Redis 7 (Alpine)** for distributed counters, session revocations, and pub/sub.
- **PostgreSQL 16 (Alpine)** for persistent tool pinning and definition drift detection.
- **Jaeger All-in-One** for distributed OpenTelemetry tracing and step latency inspection.
- **Prometheus** for metrics collection across gateway and system components.

### Scoped Zoho CRM Reference Integration (`examples/zoho-crm-mcp-server`)

Provides an end-to-end reference implementation for enterprise CRM integrations:
- **10-Minute Scoped Delegation**: Uses RFC 8693 token exchange with human delegation (`sub=sales-rep`, `act.sub=zoho-crm-sales-bot`, scopes `crm:read crm:write`).
- **Deterministic Tool Allowlists & Explicit Deny**: `zoho__delete_contact` is explicitly blocked (`deny: true`), defeating indirect injection attacks.
- **Automated PII Masking**: Customer SSN, credit card, and phone details are automatically redacted in read operations (`zoho__search_records`).
- **Human-in-the-Loop Gate (HITL)**: Modifying deal stages or customer status (`zoho__update_contact`) is intercepted into `pending` state until approved via the Admin API (`POST /admin/approvals/{id}/approve`).
- **Anti-Replay Invariant Enforcement**: Approvals are bound to `(session, tool, canonical args)` and strictly single-use (Security Invariant #9).
- **Session Revocation Kill Switch**: Sessions can be revoked instantly (`POST /admin/revoke`), rejecting the next request (Security Invariant #11).

### Sentinel Console (`/admin/console` and `/admin/`)

An air-gapped, zero-external-dependency embedded web interface for operators:
- **Human-in-the-Loop (HITL) Approvals Inbox**: Live dashboard with 1-click Approve (`POST /admin/approvals/{id}/approve`) and Deny (`POST /admin/approvals/{id}/deny`), displaying exact canonical argument diffs.
- **Audit Trail Explorer**: Live filterable feed of recent `sentinel.step` decisions (`GET /admin/audit`) powered by an internal ring buffer.
- **Session Kill Switch**: Interactive session revocation (`POST /admin/revoke`) with instant Redis Pub/Sub broadcast and in-memory invalidation.
- **Tool Hash & Quarantine Review**: Visual inspection of pinned tool hashes and drift alerts (`GET /admin/pins`).
- **Zero-Trust Web Security**: Enforces `Content-Security-Policy: default-src 'self' 'unsafe-inline'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and authenticates via Bearer tokens.



