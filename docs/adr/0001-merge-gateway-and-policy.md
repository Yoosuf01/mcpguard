# ADR 0001: Merge the MCP gateway and the policy engine into one binary

- Status: accepted
- Date: 2026-10-29 (recorded from BRIEF v2, section 3)

## Context
Policy must be decided synchronously, inside the request path, for every agent step. A separate policy
service adds a network hop to every tool call and a second thing to deploy.

## Decision
Ship one Go binary, **Shield**, with the evaluator embedded in-process (OPA's Go SDK later, same way).
Keep `internal/gateway` and `internal/policy` as separate packages so they can be split later.

## Consequences
- Lower latency, simpler deploy (`docker run`).
- Policy and gateway release together; the evaluator input document stays stable (`{principal, tool, arguments, counters}`) so a later split or a Rego port is mechanical.
