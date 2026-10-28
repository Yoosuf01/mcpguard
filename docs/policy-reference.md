# policy.yaml reference (schema v1)

Derived from `shield/internal/policy/policy.go` (the code is authoritative). `${ENV}` references are
expanded at load. Hot reload with `kill -HUP <pid>`; an invalid file is rejected and the previous policy stays active.

```yaml
version: "1"                  # required; only "1" is accepted
default_action: deny          # deny (default) | allow. Unlisted tools are hidden AND blocked when deny.
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
