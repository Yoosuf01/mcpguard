# ADR 0003: Replace fixed-window counter with sliding-window rate limiter

**Status:** Accepted | **Date:** 2026-10-23

## Context

The original `policy.Counters.rate()` used a fixed one-minute window that
resets at the start of each minute. This allows 2N calls in two seconds at
the window boundary (N at T-1s, N at T+1s), defeating the rate limit.

## Decision

Replace with `internal/ratelimit.Limiter`: a sliding window that stores
per-call timestamps and evicts those older than the interval on each `Allow()`
call. No external dependency required.

## Consequences

- **+** No double-burst possible under any traffic pattern.
- **+** O(limit) memory per key, bounded by configured limit.
- **−** Slightly higher per-call cost than an atomic counter; negligible at
  expected volumes (< 100 RPS per session).
