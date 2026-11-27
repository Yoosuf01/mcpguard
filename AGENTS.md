# AGENTS.md: instructions for AI coding agents working on MCPGuard

Read `docs/PLAN.md`, `docs/threat-model.md`, and `docs/policy-reference.md` before proposing changes.
Then read every file under the component you will touch (start with `shield/`).

## Before you change anything
- Run `cd shield && go vet ./... && go test -race ./...` and `./examples/exploit-demo/demo.sh`.
  Both must pass. If they don't, stop and report; do not "fix forward" silently.
- Work in small PRs: **one backlog item from `docs/PLAN.md` per PR**. Wait for human
  approval of the plan for each item before writing code.

## Security invariants (never break; a change needs an ADR + human sign-off)
1. The agent's bearer token is **never forwarded** upstream.
2. Cache keys **always** include verified server identity (config name) **and** caller identity.
3. A payload with `instructions` and `cacheScope: public` is **never stored**.
4. Upstream `instructions` never reach the model as trusted text.
5. Tool definition drift **quarantines** the tool (fail closed) until a human re-approves.
6. `Mcp-Method` / `Mcp-Name` headers that disagree with the body are **rejected**.
7. `default_action: deny` hides **and** blocks unlisted tools.
8. Explicit `deny: true` rules win over any allow glob.
9. Approvals are bound to `(session, tool, canonical args)` and are **single-use**.
10. Every tool-call attempt counts toward `max_steps_per_session`.
11. A revoked `sid` is rejected on the **next request**; auth decisions are never cached.
12. A policy reload that fails validation **keeps the previous policy**.

## Working rules
- Tests first for any security-relevant behavior. Never weaken a test to make a change pass.
- Keep dependencies minimal; justify every new module in the PR description.
- Fail closed: if a guard, plugin or upstream errors, deny with a clear reason.
- No secrets in code or configs. Use `${ENV}` expansion only.
- Every new decision path emits a telemetry event with a stable `rule` id.
- Update `docs/threat-model.md` and `docs/policy-reference.md` in the same PR as the code.
- Go toolchain: `export PATH="$HOME/sdk/go/bin:$PATH"` on the maintainer's machine.
