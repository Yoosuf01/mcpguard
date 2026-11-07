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
