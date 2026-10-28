# ADR 0002: Report policy denials as tool results, not protocol errors

- Status: accepted
- Date: 2026-10-29 (recorded from BRIEF v2, section 4.3)

## Context
If a blocked call comes back as a JSON-RPC error, many agent loops treat it as a transient failure and
retry blindly, sometimes with altered arguments.

## Decision
Policy denials and pending approvals return a normal `CallToolResult` with `isError: true` and a
human-readable reason, plus `_meta["dev.sentinel/decision"]` / `["dev.sentinel/rule"]`.
Protocol problems (bad JSON, header mismatch, unknown method) stay JSON-RPC errors; auth failures are HTTP 401.

## Consequences
- The model can see why it was blocked and explain it to the user.
- Forbidden tools are also hidden from `tools/list` and blocked on call, in case the model guesses the name.
