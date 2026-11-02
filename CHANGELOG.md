# Changelog

All notable changes to MCPGuard.
Follows [SemVer](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

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
