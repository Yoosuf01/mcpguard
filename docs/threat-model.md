# Threat model

Anchored on two open MCP spec issues: **MCP-2026-015** (server `instructions` folded into the system
prompt) and **MCP-2026-008** (`cacheScope` is declared by the server and not verified). These are spec
issue IDs, not CVEs. Background: see section 2 of [`BRIEF.md`](BRIEF.md).

## Operational Modes
- **Enforcing (default)**: Violations return errors (`isError: true`) and drop or withhold malicious payload data.
- **Dry-run (`dry_run: true`)**: Policy rules evaluate completely and emit audit/telemetry records tagged with `dry_run_deny` or `dry_run_pending`, but permit execution to proceed upstream. Used for enterprise adoption, baseline profiling, and non-blocking canary rollout.

## Controls C1-C4 (discovery)
- **C1 Isolate**: upstream instructions never enter the trusted prompt region (dropped, or wrapped and labelled untrusted).
- **C2 Cap**: hard 4,096-character limit.
- **C3 Bind**: cache keys bind verified server identity and caller; a payload with `instructions` is never publicly cached.
- **C4 Pin**: instructions digest pinned at first sight; drift is rejected (fail closed).

## Threats

| # | Threat | Where it enters | Shield control | Status |
|---|---|---|---|---|
| T1 | Server instructions injection (MCP-2026-015) | discovery | C1-C4 | done |
| T2 | Cross-caller cache poisoning (MCP-2026-008) | cache | identity-bound keys, refuse public+instructions, TTL cap | done |
| T3 | Tool poisoning (hidden text in descriptions/schemas) | tools/list | injection + hidden-unicode scan, quarantine | done |
| T4 | Rug pull (definition changes after approval) | tools/list | SHA-256 pin per tool, quarantine on drift | done |
| T5 | Indirect prompt injection via tool output | tools/call result | flag (warning wrapper) or block | done (heuristic) |
| T6 | Destructive actions (DROP, rm -rf, curl \| sh) | tools/call args | global + per-tool deny patterns, explicit deny | done |
| T7 | SSRF / cloud metadata access | tools/call args | private-network + scheme + domain egress policy | **partial, see G2** |
| T8 | Credential exfiltration through args | tools/call args | secret detection → deny | done |
| T9 | PII / secret leakage in results | tools/call result | redaction (Luhn-checked cards, SSN, keys, JWTs) | done |
| T10 | Runaway loops | every step | max steps per session, rate limit | **partial, see G1** |
| T11 | Privilege escalation via inherited human tokens | auth | scoped short-lived agent tokens, required scopes | done (HS256); RFC 8693 in Phase 2 |
| T12 | Header/body smuggling | transport | `Mcp-Method` / `Mcp-Name` must match body | done |
| T13 | Token passthrough to upstream | transport | agent token consumed at gateway | done |
| T14 | Sandbox escape | code execution | Firecracker microVMs | Phase 3 |

## Known gaps (verified by probe test on 2026-10-29; fixed in Phase 0, see [`PLAN.md`](PLAN.md))

- **G1 (T10)**: calls to unknown or quarantined tools return before the policy engine runs, so they do not count toward `max_steps_per_session`. Violates invariant #10.
- **G2 (T7)**: host checks only understand canonical IPs. Decimal (`2130706433`), hex (`0x7f000001`, `0x7f.0.0.1`), octal (`0177.0.0.1`), short (`127.1`) forms, trailing-dot hosts (`localhost.`, `metadata.google.internal.`) and scheme-less `localhost:8080` were allowed.

## Unverified hypotheses (do not rely on these either way)
See H1-H7 in [`PLAN.md`](PLAN.md#read-from-the-code-not-yet-reproduced-treat-as-hypotheses-until-a-test-proves-them).

## Known limitations (by design, to be documented honestly)
- Regex injection detection is a heuristic first line, not a guarantee; deterministic controls (allowlists, scopes, egress, approvals) are the real boundary.
- Egress checks inspect URLs and IP literals in arguments; they do not resolve DNS (DNS rebinding is closed by the Sandbox egress proxy in Phase 3).
- Pins are trust-on-first-use.
- v0.1 handles POST JSON-RPC only (no standalone GET SSE stream); supports `tools/*`, discovery and `ping`.

## Policy-as-Code Evaluation Engine (Phase 1b)
- **Embedded OPA / Rego Runtime**: Evaluates step-level decisions via native Open Policy Agent Go runtime (`github.com/open-policy-agent/opa/rego`).
- **Declarative YAML to Native Rego Compiler**: Converts `policy.yaml` into strict Rego v1 code (`mcpguard policy compile`).
- **Policy Testing CLI**: `mcpguard policy test <policy.yaml|policy.rego> [fixtures.json]` executes pre-deployment validation against threat scenarios and fixtures.
- **Conformance Parity**: Conformance test suite proves 100% equivalence between YAML evaluation and native Rego evaluation across all 17 security invariant test cases.
