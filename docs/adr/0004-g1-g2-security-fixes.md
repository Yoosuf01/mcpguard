# ADR 0004: G1 (step-counter bypass) and G2 (SSRF IP bypass)

**Status:** Accepted | **Date:** 2026-10-24

## G1 – Step counter bypass

**Invariant:** `engine.Evaluate` (which increments the step counter) must run
for every tool call attempt. Prior code returned early for unknown/quarantined
tools *before* calling Evaluate, allowing unbounded calls without budget impact.

**Fix:** Move `engine.Evaluate` to the top of `handleToolsCall`, before backend
resolution and quarantine checks.

## G2 – SSRF IP canonicalization bypass

**Issue:** `checkEgress` compared raw IP strings; non-canonical encodings like
`2130706433` (decimal 127.0.0.1), `0x7f000001`, `0177.0.0.1`, `127.1`, and
`::ffff:127.0.0.1` all bypassed the private-network check.

**Fix:** `internal/netutil.NormalizeHost` canonicalises all encodings to
dotted-decimal before `isInternalHost` is called.

## Consequences

- **+** All calls now consume step budget (invariant #10 restored).
- **+** SSRF protection is no longer bypassable via encoding tricks.
- **~** Tiny overhead from NormalizeHost per egress check; negligible.
