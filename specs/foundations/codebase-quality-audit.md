---
title: Codebase quality audit
status: complete
track: foundations
depends_on: []
affects:
  - audit/
  - authkit/
  - batch/
  - jwtauth/
  - llmdialect/openaichat/
  - llmdialect/openairesp/
  - md/
  - oidclogin/
  - otel/
  - pgxmigrate/
  - Makefile
  - .github/workflows/ci.yml
effort: xlarge
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Codebase Quality Audit

## Overview

Audit the shared Go packages for reproducible correctness failures, stale test
and workflow logic, and abstractions that cannot fulfill their documented
contracts. Ship only behavior-preserving cleanup or fixes backed by regression
tests; keep each implementation task small enough for one focused commit.

## Current State

The baseline passes `go test -race ./...` and `go vet ./...` with 96.5% total
statement coverage, and the Go vulnerability scanner reports no reachable
vulnerabilities. The audit nevertheless found behavioral gaps that line
coverage does not expose: stale encrypted sessions authenticate, failed LLM
streams become successful completions, oversized telemetry is forwarded after
silent truncation, and several documented extension points cannot be wired into
their consumers.

CI also maintains a manual fuzz list that has diverged from the repository's
actual `Fuzz*` functions. Coverage-only tests preserve two known defects: an
OpenAI Responses stream ending without a terminal event and indented Markdown
content being mistaken for a frontmatter fence.

## Architecture

The changes stay inside the package that owns each contract. Two abstractions
are widened at existing seams: JWT authenticators accept any token-info lookup,
and JWKS validators use a caller-provided HTTP client. The fuzz workflow moves
from duplicated manifests to discovery, making the test tree its source of
truth.

## Components

### Authentication correctness and extension points

- Validate subject and expiry before adapting `oidc.Session` into an
  `authkit.Identity`, and preserve organization roles.
- Introduce the minimal token-info lookup interface already implemented by the
  direct and cached clients.
- Carry `oidclogin.Config.HTTPClient` into `jwtauth` JWKS retrieval so custom
  trust, proxy, and mTLS policies apply consistently.

### Telemetry integrity

- Reject browser OTLP payloads over the documented limit instead of forwarding
  truncated protobufs.
- Let the OTLP log exporter parse the standard base endpoint so `/otlp` paths
  and schemes retain their defined semantics; remove the obsolete scheme
  helpers and their tests.
- Record the actual committed HTTP status when a handler calls `WriteHeader`
  more than once.

### Stream and request fidelity

- Preserve text/tool-result ordering when encoding mixed OpenAI Chat user
  messages.
- Treat official Responses `error` and `response.failed` events, plus premature
  EOF, as failures rather than synthesizing a successful terminal stream.

### Lifecycle, parsing, and cleanup

- Stop the batcher from accepting items after shutdown begins.
- Preserve indented `---` lines inside YAML block scalars.
- Return migration close failures instead of silently discarding them.
- Redact quoted environment credentials and GitHub fine-grained tokens.
- Discover fuzz targets dynamically and make CI invoke the single Make target.

## Error Handling

All fixes fail closed at the existing boundary: authentication returns
`ErrUnauthenticated`, invalid streams return a decoder error, oversized
telemetry returns HTTP 413 without contacting the collector, and migration
cleanup errors join the migration result. No exported function signatures are
removed.

## Testing Strategy

- Add one regression test for every defect that fails against the pre-fix
  implementation.
- Exercise custom TLS JWKS and OTLP endpoint paths with `httptest` servers.
- Replace tests that bless incorrect truncation/fence behavior with the correct
  contract.
- Run package tests after each commit, then repository-wide test, race, vet,
  coverage, build, and a one-iteration pass over every discovered fuzz target.

## Outcome

The audit shipped all 13 scoped tasks as independent commits. It closed the
identified correctness gaps, removed stale endpoint and fuzz-test logic, and
made the authentication extension points usable without breaking exported
callers.

### What Shipped

- Regression-tested fixes across authentication, batching, telemetry, LLM
  codecs, Markdown parsing, migration cleanup, and credential redaction.
- Minimal shared interfaces for token-info lookups and caller-controlled JWKS
  transports.
- Repository-wide fuzz discovery covering all 20 current targets from one CI
  entry point.
- A verified final state with 96.4% statement coverage, passing race, vet,
  build, formatting, and one-iteration fuzz checks.

### Design Evolution

1. JWKS fetch behavior is stored per cache so custom transports remain local,
   while the existing default-client test seam remains intact.
2. OTLP log endpoint parsing is delegated to the exporter, preserving its base
   path rules and removing obsolete scheme-rewriting helpers.
3. Batch intake and shutdown share one lifecycle lock, defining an exact
   accepted-versus-drained boundary without making `Add` blocking on I/O.
4. Access-token expiry is required for authenticated cookie sessions, while a
   missing optional dashboard-session expiry remains compatible with legacy
   sessions.

## Deferred Findings

Parallel OpenAI Chat tool-call deltas can violate canonical block ordering. It
requires a separate stream-state design because the safe options change either
latency or the IR grammar; it is intentionally not mixed into the independent
fixes above.

## Task Breakdown

| Child spec | Depends on | Effort | Status |
|---|---|---|---|
| [Credential redaction](codebase-quality-audit/credential-redaction.md) | — | small | complete |
| [Batch shutdown lifecycle](codebase-quality-audit/batch-shutdown-lifecycle.md) | — | small | complete |
| [Session authentication validation](codebase-quality-audit/session-authentication-validation.md) | — | small | complete |
| [Token-info lookup abstraction](codebase-quality-audit/tokeninfo-lookup-abstraction.md) | — | small | complete |
| [JWKS HTTP client](codebase-quality-audit/jwks-http-client.md) | — | medium | complete |
| [Telemetry proxy body limit](codebase-quality-audit/telemetry-proxy-body-limit.md) | — | small | complete |
| [OTLP log base endpoint](codebase-quality-audit/otlp-log-base-endpoint.md) | — | medium | complete |
| [HTTP status recording](codebase-quality-audit/http-status-recording.md) | — | small | complete |
| [OpenAI Chat message ordering](codebase-quality-audit/openai-chat-message-ordering.md) | — | small | complete |
| [OpenAI Responses terminal failures](codebase-quality-audit/openai-responses-terminal-failures.md) | — | medium | complete |
| [Markdown frontmatter fence](codebase-quality-audit/markdown-frontmatter-fence.md) | — | small | complete |
| [Migration close errors](codebase-quality-audit/migration-close-errors.md) | — | small | complete |
| [Fuzz workflow discovery](codebase-quality-audit/fuzz-workflow-discovery.md) | — | small | complete |

All tasks are independent. The recommended order above starts with security and
lifecycle fixes, then transport/codec correctness, then repository workflow
cleanup.

## Implementation Notes

### Status

Complete in commits `0d04d24` through `d166d44` on 2026-07-21.

### What Was Done

- Implemented and regression-tested every child spec in one focused commit.
- Removed stale OTLP endpoint helpers and their obsolete tests, and replaced
  copied fuzz manifests with repository discovery.

### What Was Not Done

- Parallel OpenAI Chat tool-call delta ordering remains deferred because a safe
  fix requires a separate stream-state and IR design.

### Follow-ups

- Create a dedicated spec for parallel tool-call streaming semantics before
  changing latency or canonical block ordering.
