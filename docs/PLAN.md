# MCPGuard: Project Plan

Status as of **2026-10-29**. This file tracks the executable roadmap derived from the architecture review of `shield/`.
Every item below is **one PR-sized task**. Per the brief, no task starts until you approve it.

## 1. Where we are (verified, not assumed)

| Check | Result |
|---|---|
| `go vet ./...` (Go 1.27.3, darwin/arm64) | clean |
| `go test -race -count=1 ./...` | all 4 packages with tests pass; 38 test cases |
| `examples/exploit-demo/demo.sh` | runs end to end: attacks succeed against raw servers; through Shield, instructions are withheld, injection flagged, `DROP` denied, exfil denied, SSRF to `169.254.169.254` denied, PII redacted, revoked session rejected |
| Packages with **no tests** | `cmd/shield`, `hitl`, `identity`, `mcp`, `telemetry` |
| Code size | ~3.2k lines of Go, one dependency (`yaml.v3`) |

Repo state: `git init` done, baseline committed unmodified, then a mechanical module-path rename
`your-org` → `Yoosuf01` (no behavior change). Go lives in `~/sdk/go` (Homebrew is broken on this
machine and was left alone): `export PATH="$HOME/sdk/go/bin:$PATH"`.

## 2. Findings from reading every file

### Confirmed by a probe test (then deleted; reproduce by writing the test in Phase 0)
| ID | Finding | Evidence |
|---|---|---|
| F1 | **Invariant #10 is not fully true.** Unknown-tool (and quarantined-tool) calls return before `engine.Evaluate`, so they never increment the step counter. A hijacked agent can loop on bad names forever. | 60 `nosuch__tool` calls, then a legitimate call under a 25-step budget was still **allowed** |
| F2 | **SSRF filter bypass by IP encoding.** `isInternalHost` only understands canonical IPs. | `http://2130706433/`, `http://0x7f000001/`, `http://0x7f.0.0.1/`, `http://0177.0.0.1/`, `http://127.1/`, `http://localhost./`, `http://metadata.google.internal./` and scheme-less `localhost:8080/admin` were all **allowed** under the global-only egress policy. Canonical `169.254.169.254`, `[::ffff:7f00:1]` and `LOCALHOST` were blocked. |

### Read from the code, **not yet reproduced** (treat as hypotheses until a test proves them)
| ID | Hypothesis | Where |
|---|---|---|
| H1 | Invariant #12 (bad reload keeps old policy) has no test; the reload loop lives in `main()` so it is untestable as written. The brief already lists this as a Phase 1 TODO. | `cmd/shield/main.go` |
| H2 | On SIGHUP only `engine.Swap` runs; `DiscoveryGuard` was built once from the *old* discovery config, so changes to `discovery:` in policy.yaml probably don't apply until restart. | `gateway.New`, `main.go` |
| H3 | `Counters` (steps/rate) and `hitl.Store.byID` never evict, so memory grows per session for the life of the process. | `engine.go`, `hitl.go` |
| H4 | Legacy (2025-06-18) backends use **one upstream session shared by all callers**, so session state could bleed between users. Needs a design decision (per-caller sessions vs documenting it). | `upstream.go` |
| H5 | `GET /admin/approvals` returns full tool arguments, which may contain sensitive data; admin token is the only gate. | `admin.go` |
| H6 | The first demo run exited right after its first request; the second run was fine. Probably the fixed `sleep 1` racing server startup, but the cause is **unconfirmed**. | `demo.sh` |
| H7 | `gofmt -l` flags `gateway_test.go` (pre-existing trailing blank lines). | tests |

## 3. Phase 0: harden the baseline (new; ~3 days; recommended before Backlog #1)

Rationale: Phase 1 adds Redis, OTel and new proxy surfaces on top of this code. Fixing F1/F2 first
keeps the launch claim ("blocks the chain, invariants have tests") true.

| # | Task | Acceptance |
|---|---|---|
| 0.1 | **Fix F1**: count every `tools/call` attempt (unknown, quarantined, denied) toward steps. Test first. | New failing test goes green; invariants 7, 10 still pass |
| 0.2 | **Fix F2**: canonicalize hosts before egress checks (strip trailing dot, parse decimal/hex/octal/short IPv4, unwrap v4-mapped v6); table test with every encoding above | All encodings blocked; scheme-less `host:port` documented as a known limitation or handled |
| 0.3 | Extract policy reload into a testable function; add the invariant #12 test; verify/fix H2 | Test proves old policy survives a bad file |
| 0.4 | Add tests for the untested packages: `identity` (alg=none, bad sig, expiry, aud/iss, revoked), `hitl` (single-use, args change), `mcp` (batch rejected, bad version) | Each security invariant has a named test |
| 0.5 | Replace `sleep 1` in `demo.sh` with a readiness poll; `gofmt` the test file; add CI | CI green on a clean clone |
| 0.6 | Decide H4 and H5 (ADR), implement the smaller option | ADR merged |

## 4. Phase 1: Shield core (brief section 9.1), proposed order

The brief's order is kept; **two moves are proposed** (marked ★) and need your approval.

| # | Task | Notes / acceptance |
|---|---|---|
| 1 | OpenTelemetry recorder | span `mcp.<method>` per step, attrs `sentinel.*`, `traceparent` in/out, Jaeger in compose |
| ★2 | **Benchmarks (brief #10) moved up** | Get a latency baseline *before* Redis adds network hops; target < 2 ms p99 added for an allowed call |
| 3 | Redis-backed `Counters`, `hitl.Store`, `Revocations`, `PinStore` (+ memory versions kept) | multi-replica correctness test; also resolves H3 via TTLs |
| 4 | Postgres `PinStore` + `shield pins list\|diff\|approve` CLI | diff shown before re-approval; invariant 5 test |
| 5 | Proxy `resources/*` and `prompts/*` | `resources/read` URI goes through egress check; `prompts/get` text scanned |
| 6 | stdio backends | env allowlist + restart policy; first real target: an official MCP server (see section 6) |
| ★7 | **`dry_run: true` (from #7) moved up** | adoption-critical: log decisions without enforcing; rest of #7 (schema constraints, time conditions) stays later |
| 8 | Server→client streaming (progress, sampling/elicitation behind policy) | SSE relay |
| 9 | Policy features: JSON-schema arg constraints, time/env conditions | |
| 10 | Approvals UX: Slack/webhook notifier, HMAC-signed short-lived links | |
| 11 | Packaging: distroless Dockerfile, goreleaser, `examples/claude-code`, `examples/cursor` | `docker run` quickstart works on a clean machine |
| 12 | Tag `shield v0.1.0` + README with real benchmark numbers + recorded demo | launch moment |

Each PR: tests first for security behavior, update `threat-model.md` + `policy-reference.md`,
emit telemetry with a stable `rule` id, justify any new dependency.

## 5. Later phases (unchanged from the brief)

| Phase | Weeks | Summary |
|---|---|---|
| 1b Policy-as-code | 5-6 | embedded OPA, YAML→Rego compiler, Python plugin SDK, `shield policy test`; existing tests become the conformance suite |
| 2 Identity | 7-9 | RFC 8693 exchange, ES256 + JWKS, registry, Redis revocation, audit log, `JWKSVerifier` |
| 3 Sandbox | 10-16 | 3a hardened Docker driver, 3b Firecracker + warm pool + vsock agent; escape-attempt suite shared by both drivers |
| 4 Fabric | 17+ | compose all-in-one, Helm, Console UI, Zoho CRM example |

## 6. How your GitHub stars and `morluto/rea` fit

Based on **repo descriptions only** (I have not read their code); verify before depending on any.

| Repo | Relevance | Use |
|---|---|---|
| `morluto/rea` (MIT) | An MCP server for reverse engineering (binaries, Electron, .NET). Very high-power tools. | Best **showcase backend**: "Shield in front of a dangerous MCP server" demo; also a realistic stdio-backend test for Phase 1 #6. It is installed via `npx rea-agents`, so pin a version, run from a trusted dir, and ideally run it inside the Phase 3 sandbox. The README warns about look-alike repos; use only morluto/rea, rea.tools or the `rea-agents` npm package. |
| `UsefulSoftwareCo/executor` (MIT) | "Integration layer" exposing OpenAPI/MCP/GraphQL to agents | Candidate upstream backend and a positioning/competitor reference for the README comparison table |
| `JuliusBrussee/caveman` (Go, Apache-2.0) | Go proxy for coding agents | Read for Go proxy/packaging patterns; not a dependency |
| `huggingface/smolagents`, `agno-agi/agno` (Apache-2.0) | Agent frameworks | `examples/` clients (smolagents also has code-execution sandboxes worth studying for Phase 3) |
| `google/agents-cli`, `GoogleCloudPlatform/agent-starter-pack` | Agent deploy templates | Reference for `deploy/` and an example client |
| `moabukar/CKS-Exercises…`, Trivy (topic) | K8s security | Phase 3/4 hardening checklist for Helm + sandbox |
| `trycompai/crm`, `melgarafael/DeskcommCRM` (MIT) | Agentic CRMs | Inspiration for the Zoho CRM example scenario |
| `colbymchenry/codegraph`, `Graphify-Labs/graphify` | Code knowledge graphs | Optional dev tooling for coding agents working on this repo |
| `miqdadbadjuber/anti-slop` | UI design rules | Phase 4 Console UI |
| The other ~22 stars (geo, voice, OCR, interview prep, etc.) | Not relevant | none |

Also referenced by the brief and worth cloning when needed: `themsquared/mcp-redteam-lab`
(attack scenarios for the demo) and `lasso-security/mcp-gateway` (competitor, MIT).

## 7. Decisions I need from you

1. Approve **Phase 0** as the first work (or tell me to jump straight to Backlog #1).
2. Approve the two re-orderings (★ benchmarks earlier, ★ `dry_run` earlier).
3. H4: per-caller upstream sessions (safer, more connections) vs documenting the shared session?
4. Should I create the GitHub repo `Yoosuf01/mcpguard` (needs your auth), or will you push?
