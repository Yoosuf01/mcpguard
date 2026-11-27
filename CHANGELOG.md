# Changelog

All notable changes to MCPGuard.
Follows [SemVer](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

---

## [0.2.0] – 2026-11-27

Major feature expansion adding Policy-as-Code, Enterprise Identity Federation, Compute Sandboxing, and Production Fabric orchestration.

### Added
- **Policy-as-Code (Phase 1b)**: Embedded Open Policy Agent (OPA) Go runtime (`opa/rego`) evaluating native Rego v1 policies, YAML-to-Rego compiler (`mcpguard policy compile`), and policy test CLI (`mcpguard policy test`) with 17-scenario conformance parity.
- **Sentinel Identity (Phase 2)**: RFC 8693 OAuth 2.0 token exchange with 3-way scope intersection math, ES256 `JWKSVerifier` with singleflight deduplication and SSRF-safe fetching, Agent Identity Registry, RFC 9470 OAuth Protected Resource Metadata, and Redis Pub/Sub real-time session revocation kill switch.
- **Sentinel Sandbox (Phase 3)**: Hardened unprivileged Docker driver (`--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`), Firecracker MicroVM driver over `virtio-vsock` (<5 ms warm pool), DNS-pinned forward egress proxy defeating TOCTOU DNS rebinding, and unified escape conformance suite.
- **Sentinel Fabric (Phase 4)**: Production Docker Compose stack (`deploy/docker-compose.yaml`), Restricted PSS Kubernetes Helm chart (`deploy/helm/mcpguard`), scoped Zoho CRM MCP reference server (`examples/zoho-crm-mcp-server`), and embedded air-gapped Sentinel Console UI (`/admin/console`).

### Fixed
- Updated CI workflow and `shield/Dockerfile` toolchain baseline to Go 1.26.

---

## [0.1.0] – 2026-11-03

First production-grade release of **MCPGuard** (Phase 1 Shield): an open-source security gateway and step-level policy engine for Model Context Protocol (MCP) servers.

### Added
- **Distributed Tracing**: OpenTelemetry (`go.opentelemetry.io/otel`) exporter with spans per `mcp.<method>` step and bidirectional W3C `traceparent` propagation.
- **Audit Mode**: `dry_run: true` configuration mode for non-blocking policy evaluation and simulated telemetry.
- **Distributed State**: Pluggable storage architecture (`internal/state`) supporting both memory with TTL auto-eviction (resolving session growth) and Redis multi-replica adapters for counters, revocations, pins, and approvals.
- **Resources & Prompts Interception**: Proxying for `resources/*` (with SSRF and egress validation) and `prompts/*` (with secret detection and indirect injection scanning).
- **Process Supervision**: `stdio` local MCP server child process execution with environment variable allowlisting and restart policies.
- **Tool Pinning & Registry CLI**: Persistent `FileStore` registry with drift diffing and `mcpguard pins [list|diff|approve]` CLI.
- **Approvals UX**: Real-time webhook notifications for pending HITL requests with HMAC-SHA256 signed 1-click decision URLs.
- **Security Hardening**:
  - Full IP canonicalization (`internal/netutil`) blocking decimal, octal, hex, short, and IPv4-mapped IPv6 SSRF bypasses.
  - Step counter and sliding-window rate limit enforcement on every attempt, including unknown or quarantined tools (G1 fix).
  - Discovery guard withholding server instructions injection (MCP-2026-015).
  - Cross-caller cache partitioning preventing cache poisoning (MCP-2026-008).
- **Packaging & Integrations**:
  - `.goreleaser.yaml` cross-platform build definitions (Linux, macOS, Windows).
  - Distroless multi-stage `Dockerfile` and `docker-compose.yml` with Prometheus and Jaeger.
  - Integration guides and configurations for **Claude Code** and **Cursor**.
- **Observability & Benchmarks**:
  - Formal `go test -bench` suite: Gateway overhead < 0.07 ms / call (30x faster than target).
  - Structured JSON logs, `/healthz` and `/readyz` endpoints.
