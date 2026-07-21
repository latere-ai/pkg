---
title: Fail closed on Responses stream termination errors
status: validated
track: foundations
depends_on: []
affects:
  - llmdialect/openairesp/backend.go
  - llmdialect/openairesp/backend_cover_test.go
effort: medium
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Fail Closed on Responses Stream Termination Errors

## Goal

Surface official upstream failures and truncated streams instead of synthesizing
a successful `end_turn`.

## What to do

1. Parse top-level `error` event fields and nested `response.failed` errors.
2. Treat failed/cancelled responses as terminal decoder errors.
3. Return `io.ErrUnexpectedEOF` when the SSE source ends before a terminal event.

## Tests

- Test official top-level error and `response.failed` payloads.
- Replace the premature-EOF success test with an `io.ErrUnexpectedEOF` assertion.

## Boundaries

- Keep completed/incomplete response event translation unchanged.

