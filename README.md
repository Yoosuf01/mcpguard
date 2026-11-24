<div align="center">

# MCPGuard 🛡️

**A production-grade security gateway for [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers.**

[![CI](https://github.com/Yoosuf01/mcpguard/actions/workflows/ci.yml/badge.svg)](https://github.com/Yoosuf01/mcpguard/actions)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-1.23%2B-00ADD8?logo=go)](https://go.dev)

MCPGuard sits between your AI agents and their MCP tool servers, enforcing
**fine-grained security policies** before any tool call reaches the backend.

</div>

---

## Why MCPGuard?

| Threat | Defence |
|---|---|
| Runaway agent loops | Per-session step limits + sliding-window rate limiting |
| Prompt injection in arguments | Deny-pattern matching |
| Secret exfiltration | Credential detection (AWS keys, JWTs, GitHub tokens…) |
| SSRF via tool arguments | Full IP canonicalization – blocks `2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`… |
| Upstream instruction injection | Discovery guard (MCP-2026-015) |
| Tool rug-pulls / poisoning | Hash-pinned tool registry with quarantine |
| Unreviewed sensitive actions | Human-in-the-loop (HITL) approval workflow |
| Unaudited calls | Append-only JSON audit log + X-Request-ID correlation |

## Architecture

```
AI Agent / MCP Client
        │ JWT-authenticated HTTP/JSON-RPC
        ▼
┌───────────────────────────────────────────┐
│           MCPGuard Gateway :8080          │
│                                           │
│  Identity (JWT) · Discovery Guard        │
│                                           │
│         ┌─────────────────────┐          │
│         │    Policy Engine    │          │
│         │  steps · rate limit │          │
│         │  allowlist · egress │          │
│         │  secrets · HITL     │          │
│         └──────────┬──────────┘          │
│                    │ Allow               │
│         ┌──────────▼──────────┐          │
│         │   Upstream Proxy    │          │
│         │ circuit · cache     │          │
│         └──────────┬──────────┘          │
└────────────────────┼──────────────────────┘
           MCP Server A   MCP Server B
```

## Quick start

### One command (Docker Compose)

```bash
git clone https://github.com/Yoosuf01/mcpguard.git && cd mcpguard
docker compose up
```

| Service | URL |
|---|---|
| Gateway | http://localhost:8080 |
| Admin API | http://localhost:8081 |
| Prometheus | http://localhost:9090 |
| Jaeger | http://localhost:16686 |

### Binary

```bash
make build
export MCPGUARD_HS256_SECRET="your-32-plus-byte-secret-here-!!"
export MCPGUARD_ADMIN_TOKEN="your-admin-token"
./bin/mcpguard -config shield/configs/shield.yaml
```

### Mint a dev JWT

```bash
make mint-token
```

## Policy example

```yaml
# shield/configs/policy.yaml
default_action: deny

global:
  block_secrets_in_arguments: true
  egress:
    block_private_networks: true
    allow_domains: ["api.openai.com", "*.anthropic.com"]

agents:
  - id: customer-support-bot
    max_steps_per_session: 50
    rate_limit_per_minute: 20
    tools:
      - name: "crm/get_customer"
        require_scope: "crm:read"
      - name: "db/run_query"
        deny_patterns: ["DROP\\s+TABLE", "DELETE\\s+FROM"]
      - name: "payments/charge"
        require_approval: true   # always requires human approval
```

## Performance Benchmarks

Measured on Apple M4 using `go test -bench=. -benchmem`:

| Benchmark | Latency | Memory / Op | Target | Status |
|---|---|---|---|---|
| **Step-Level Policy Evaluation** (`BenchmarkPolicy_Evaluate`) | **12.3 µs** (0.012 ms) | 1.98 KB | < 1 ms | ✅ 80x faster than target |
| **Full Gateway Request Interception** (`BenchmarkGateway_AllowedCall`) | **66.2 µs** (0.066 ms) | 36.5 KB | < 2 ms | ✅ 30x faster than target |

> MCPGuard adds **less than 0.07 ms of overhead** to an end-to-end tool call while enforcing step limits, rate limits, secret detection, IP canonicalization/SSRF filters, and OpenTelemetry trace propagation.

## Observability

| Surface | Where |
|---|---|
| Structured JSON logs | stdout (`mcpguard.step` events) |
| Prometheus metrics | `http://localhost:8081/metrics` |
| Distributed traces (OTel) | Jaeger `http://localhost:16686` |
| Audit log | stdout (JSON lines, one record per decision) |

## Comparison: MCPGuard vs. Other Platforms

| Capability | **MCPGuard (Sentinel)** | **WSO2 Agent Manager** | **Archestra** | **Lasso Security** | **Runlayer** |
|---|---|---|---|---|---|
| **License** | **Apache 2.0** | Apache 2.0 | AGPL-3.0 | MIT | Commercial / Closed |
| **Form Factor** | **Single Go Binary (< 35 MB)** | K8s / OpenChoreo Platform | K8s-native Pods | Python Gateway | Hosted SaaS / Enterprise |
| **5-Minute Start** | **Yes** (Drop-in before agent) | No (Heavy platform setup) | No (Requires K8s cluster) | Yes | No (SaaS sign-up) |
| **Step-Level Policy Engine** | **Yes** (Go + Native Rego/OPA) | Yes (40+ Guardrails) | Deterministic Rules | Regex Plugin | Proprietary ToolGuard |
| **Agent Identity (RFC 8693)** | **Yes** (3-Way Scope Math, ES256) | Yes (Enterprise IdP) | No | No | Yes (IAM) |
| **Compute Sandbox Isolation** | **Yes** (Docker + Firecracker KVM) | Yes (K8s Sandbox) | K8s Pods Only | No | Yes (Cloud Containers) |
| **DNS-Pinned Egress Proxy** | **Yes** (Defeats DNS rebinding) | No | No | No | No |
| **Console Web UI** | **Yes** (Embedded zero-dependency) | Yes (Web Portal) | Yes (Web UI) | No | Yes (Web Dashboard) |

---

## Roadmap & Milestone Progress

- [x] **Phase 0: Baseline Hardening**: Step counting on every call attempt (Invariant #10), strict SSRF host canonicalization, hot policy reload resilience (Invariant #12).
- [x] **Phase 1: Shield Core MVP**: OpenTelemetry tracing (`sentinel.*` spans), `dry_run: true` audit mode, Redis distributed state, proxying `resources/*` & `prompts/*`, stdio backend child supervision, tool pins CLI (`mcpguard pins`), 1-click webhook approvals, distroless Docker packaging, sub-0.07ms p99 benchmarks.
- [x] **Phase 1b: Policy-as-Code**: Embedded Open Policy Agent (OPA) Go runtime (`rego`), YAML-to-Rego compiler (`mcpguard policy compile`), and policy test CLI (`mcpguard policy test`).
- [x] **Phase 2: Sentinel Identity**: RFC 8693 token exchange with 3-way scope intersection math, ES256 `JWKSVerifier` with singleflight deduplication and SSRF-safe fetching, Agent Identity Registry, RFC 9470 OAuth Protected Resource Metadata (`/.well-known/oauth-protected-resource`), and Redis Pub/Sub real-time session revocation kill switch.
- [x] **Phase 3: Sentinel Sandbox**: Unified escape conformance suite, hardened unprivileged Docker driver (`--network none`, `--read-only`, tmpfs, `--cap-drop ALL`, `no-new-privileges`), Firecracker MicroVM driver over virtio-vsock with <5ms warm pool, and DNS-pinned forward egress proxy defeating TOCTOU DNS rebinding.
- [x] **Phase 4: Sentinel Fabric**: Production Docker Compose stack (`deploy/docker-compose.yaml`), production Kubernetes Helm Chart (`deploy/helm/mcpguard`) conforming to Restricted Pod Security Standards, real-world scoped Zoho CRM reference integration (`examples/zoho-crm-mcp-server`), and embedded air-gapped Sentinel Console UI (`/admin/console`).


## Contributing & Security

See [CONTRIBUTING.md](CONTRIBUTING.md) · [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md)

## License

Apache 2.0 © 2026 Muhamed Yoosuf — see [LICENSE](LICENSE).
