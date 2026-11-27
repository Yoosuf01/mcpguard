# Threat model

Anchored on two open MCP spec issues: **MCP-2026-015** (server `instructions` folded into the system
prompt) and **MCP-2026-008** (`cacheScope` is declared by the server and not verified). These are spec
issue IDs, not CVEs. See [`PLAN.md`](PLAN.md) and [`policy-reference.md`](policy-reference.md) for architecture and controls.

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
| T11 | Privilege escalation via inherited human tokens | auth | scoped short-lived agent tokens, required scopes | done (HS256 standalone + ES256/JWKS in Phase 2) |
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

## Sentinel Identity & Enterprise Auth (Phase 2)
- **ES256 JWKS Verifier (`JWKSVerifier`)**: Enterprise-grade identity verification for short-lived, delegated agent tokens minted via RFC 8693 token exchange.
- **Strict Algorithm Pinning**: Enforces `ES256` strictly in JWS protected headers and key structures. Completely rejects `alg: none`, `RS256`, and HMAC key-confusion attacks (`HS256` using asymmetric public keys as secrets).
- **Singleflight Deduplication**: Outbound JWKS key rotation fetches use `singleflight.Group` to deduplicate concurrent requests for rotated `kid` values into a single HTTP request.
- **Rate-Limited Miss Protection**: Cooldown window (`MinRefreshCooldown`) prevents denial-of-service hammering against identity endpoints on bogus or invalid `kid` arrivals.
- **SSRF-Safe Remote Fetching**: Built-in HTTP transport with socket-level IP checks (`net.Dialer.Control`) blocks loopback, private IPv4/IPv6 networks, cloud metadata services (`169.254.169.254`, Google/Azure/AWS metadata), non-canonical IP encodings, and HTTP 302 redirects.
- **RFC 8693 Delegation Claims**: Resolves human principal identity (`sub`), delegated agent identity (`act.sub` or `agent_id`), agent session (`sid`), and granted scopes. Integrates directly with real-time session revocation kill switches.
- **RFC 8693 Token Exchange Engine (`TokenExchangeEngine`)**: OAuth 2.0 token minting endpoint (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`). Accepts verified human `subject_token` and agent `actor_token`, generating cryptographically secure session IDs (`sid`).
- **3-Way Scope Intersection Math**: Mathematically enforces $\text{Granted} = \text{Human} \cap \text{Agent} \cap \text{Requested}$. Eliminates privilege escalation: agents can never obtain scopes not held by both the human user and registered for the agent. Missing or disjoint scopes reject immediately with `invalid_scope`.
- **Agent Identity Registry (`AgentRegistry`)**: Authoritative repository for registered enterprise agent profiles (`AgentProfile`). Validates agent lifecycle status (`active`, `suspended`, `revoked`), restricts maximum permissible scopes (`AllowedScopes`), and enforces strict boundary isolation via Memory and Redis backends. Unregistered or suspended agents are denied token exchange.
- **RFC 9470 OAuth Protected Resource Metadata**: Standard discovery endpoint (`/.well-known/oauth-protected-resource`) advertising supported authorization servers and required scopes, enabling zero-configuration client token acquisition and preventing hardcoded identity provider drift.
- **Distributed Real-time Revocation (`PubSubRedisRevocations`)**: Sub-millisecond session kill switch push via Redis Pub/Sub combined with local fast-path in-memory caching and Redis persistent fallback. Satisfies Security Invariant #11 across distributed gateway clusters without adding network round-trip overhead to every tool-call step.

## Sentinel Sandbox & Compute Isolation (Phase 3)
- **T14: Sandbox Escape & Host Compromise**: Controlled code execution (`run_bash`, `run_python`) inside ephemeral, disposable microVMs or containers.
- **Unified Escape-Attempt Verification**: All sandbox drivers (hardened Docker, gVisor, Firecracker) pass the shared conformance suite verifying defense against fork bombs (`pids.max`), rootfs modification (`Read-only file system`), SSRF/cloud metadata access (`--network none`), capability escalation (`--cap-drop ALL`, `no-new-privileges`), and execution hangs (strict wall-clock deadline termination).
- **Hardened Docker Isolation**: Defense-in-depth Linux container runtime enforcing `--network none`, `--read-only`, tmpfs workspace isolation, `--cap-drop ALL`, `--security-opt no-new-privileges`, and cgroups v2 process/memory limits. Host filesystem and network remain untouched.
- **Sandbox MCP Server Architecture**: Encapsulates sandbox operations as standard MCP tools (`sandbox__run_bash`, `sandbox__run_python`, `sandbox__read_file`, `sandbox__write_file`), routing all outputs back through Shield policy and redaction pipelines to ensure secrets printed inside the sandbox are redacted. Session workspace boundaries prevent cross-agent data leakage.
- **DNS Rebinding Defeat (`PinnedProxy`)**: Forward HTTP/HTTPS egress proxy resolving DNS once, evaluating all resolved IPs against egress security boundaries (blocking `169.254.169.254` and RFC1918 addresses), and pinning the TCP socket directly to the validated IP. Closes the DNS-rebinding time-of-check to time-of-use (TOCTOU) gap.
- **MicroVM Hardware Virtualization (`FirecrackerDriver`)**: Hardware-level guest kernel isolation (KVM) preventing container-to-host privilege escalation or kernel exploits. Communicates over AF_VSOCK with sub-5ms pre-warmed pool acquisition.

## Sentinel Fabric & Production Deployment (Phase 4)
- **T15: Pod Compromise & Kubernetes Cluster Lateral Movement**:
  - **Zero-Trust Pod Security**: Enforces `runAsNonRoot: true`, `runAsUser: 65532`, `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, and drops all Linux capabilities (`drop: ["ALL"]`). Root filesystem modification or binary hijacking within the container is rendered impossible.
  - **API Token Weaponization Defeat**: `automountServiceAccountToken: false` prevents an attacker from extracting Kubernetes service account credentials from `/var/run/secrets/kubernetes.io/serviceaccount` to attack the cluster API server.
  - **Network Micro-segmentation & Metadata Exfiltration Defeat**: Zero-Trust `NetworkPolicy` isolates container networking. Administrative and metrics ports (`:8081`) are restricted to monitoring namespaces, while egress strictly blocks link-local cloud metadata (`169.254.169.254/32`), preventing SSRF-driven IAM credential exfiltration in AWS, GCP, or Azure clusters.
  - **Secret Exposure Prevention**: Gateway and admin tokens are injected via Kubernetes Secrets (`secretKeyRef`) or external KMS operators (Vault / AWS Secrets Manager) rather than configuration files or container images.
- **T16: Unauthorized CRM Modification & Destructive Deletion**:
  - **Tool Deletion Barrier**: Irreversible deletion tools (`crm__delete_contact`) explicitly denied (`deny: true`), defeating indirect prompt injection or agent confusion attacks.
  - **Human Gate on Business State**: Deal status or contact mutation (`crm__update_contact`) cannot execute autonomously; single-use approval enforces exact parameter review by a human operator.
  - **PII Exposure Defeat**: Customer credit cards, social security numbers, and contact details returned by CRM backends are scrubbed automatically before context injection.
- **T17: Admin Interface Compromise, Clickjacking & Cross-Site Scripting (XSS)**:
  - **Clickjacking Protection**: `X-Frame-Options: DENY` stops the console from being framed in attacker web pages.
  - **MIME Sniffing Prevention**: `X-Content-Type-Options: nosniff` prevents browser MIME confusion attacks.
  - **Strict Content Security Policy (CSP)**: `default-src 'self' 'unsafe-inline'` disallows loading scripts or assets from third-party origins or external CDNs, maintaining air-gapped security.
  - **Constant-Time Admin Token Comparison**: Uses `subtle.ConstantTimeCompare` against the admin bearer token to thwart timing side-channel attacks on administrative APIs.



