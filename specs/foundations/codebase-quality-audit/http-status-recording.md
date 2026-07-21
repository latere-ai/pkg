---
title: Record committed HTTP response status
status: validated
track: foundations
depends_on: []
affects:
  - otel/http.go
  - otel/http_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Record Committed HTTP Response Status

## Goal

Keep telemetry status labels aligned with the response status actually committed
by `net/http` when handlers call `WriteHeader` repeatedly.

## What to do

1. Ignore repeated final `WriteHeader` calls in the wrapper.
2. Continue allowing informational 1xx headers before the final status.
3. Preserve response-controller unwrapping.

## Tests

- Assert a repeated final status records and writes only the first final code.
- Assert an informational header can precede the recorded final code.

## Boundaries

- Do not change route or span labeling.

