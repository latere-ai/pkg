---
title: Reject oversized telemetry payloads
status: complete
track: foundations
depends_on: []
affects:
  - otel/proxy.go
  - otel/proxy_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Reject Oversized Telemetry Payloads

## Goal

Return HTTP 413 before contacting the collector instead of forwarding a silently
truncated OTLP protobuf.

## What to do

1. Read at most the configured limit plus one byte.
2. Reject payloads larger than the limit with `StatusRequestEntityTooLarge`.
3. Preserve exact-limit forwarding.

## Tests

- Assert limit-plus-one returns 413 and makes zero upstream requests.
- Assert an exact-limit body is forwarded intact.

## Boundaries

- Do not change the response-body cap or allowed methods.

## Implementation Notes

### Status

Complete in `091200e` on 2026-07-21.

### What Was Done

- Rejected limit-plus-one payloads before upstream and tested exact-limit data.

### Decisions Made During Implementation

- Read one byte beyond the cap to distinguish exact-size from oversized input.

### Follow-ups

None.
