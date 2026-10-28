# Changelog

All notable changes to MCPGuard.
Follows [SemVer](https://semver.org) and [Keep a Changelog](https://keepachangelog.com).

---

## [Unreleased]

### Added
- `internal/errors`: typed domain error hierarchy (Code, Retryable, Unwrap)
- `internal/requestid`: X-Request-ID correlation middleware
- `internal/ratelimit`: sliding-window rate limiter (no double-burst at boundary)
- `internal/config`: config loader with multi-error validation and env expansion
- `internal/audit`: append-only JSON-lines audit writer
- `internal/netutil`: NormalizeHost – canonicalize all non-standard IP encodings
- `internal/middleware`: composable Chain, Recover, Timeout, CORS builders
- `internal/health`: /healthz liveness and /readyz readiness handlers
- `internal/version`: build-time metadata via ldflags
- `Dockerfile` (multi-stage, distroless) + `docker-compose.yml`
- `Makefile` with build/test/lint/docker/compose/mint-token targets
- `CONTRIBUTING.md`, GitHub issue templates, PR template
- `SECURITY.md`, `CODE_OF_CONDUCT.md`
- ADR 0003 (sliding-window limiter), ADR 0004 (G1+G2 fixes)

### Fixed
- **G1** – Step counter now fires for *every* tool call, including unknown and
  quarantined tools. Previously the counter was bypassed before `engine.Evaluate`
  ran, allowing a misbehaving agent to exceed `max_steps_per_session` unbounded.
- **G2** – Egress SSRF check now normalises non-canonical IP encodings
  (decimal `2130706433`, hex `0x7f000001`, octal `0177.0.0.1`, short `127.1`,
  trailing-dot, IPv6-mapped `::ffff:127.0.0.1`) before the private-network check.

### Changed
- Renamed: Sentinel → MCPGuard
- Module: `github.com/Yoosuf01/sentinel` → `github.com/Yoosuf01/mcpguard`
- Log keys: `sentinel.*` → `mcpguard.*`; env vars: `SENTINEL_*` → `MCPGUARD_*`

---

## [0.1.0] – 2026-10-01

Initial MCPGuard Shield baseline — JWT gateway, policy engine, discovery guard,
HITL approvals, secret detection, output scanning, circuit breakers, hot-reload.
