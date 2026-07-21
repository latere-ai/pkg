---
title: Preserve OTLP log base endpoint paths
status: validated
track: foundations
depends_on: []
affects:
  - otel/logs.go
  - otel/logs_test.go
effort: medium
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Preserve OTLP Log Base Endpoint Paths

## Goal

Use the exporter’s standard environment parsing so a general endpoint ending in
`/otlp` sends logs to `/otlp/v1/logs` with the declared scheme.

## What to do

1. Stop rewriting the general endpoint as a host-only exporter option.
2. Remove `useInsecure`, `stripScheme`, their explanatory comments, and their tests/fuzzer.
3. Keep local-only fallback behavior unchanged.

## Tests

- Emit and flush a log to a test base endpoint and assert `/otlp/v1/logs`.

## Boundaries

- Do not change trace/metric setup or logging fan-out semantics.

