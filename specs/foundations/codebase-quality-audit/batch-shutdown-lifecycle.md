---
title: Reject batch items after shutdown
status: validated
track: foundations
depends_on: []
affects:
  - batch/batch.go
  - batch/batch_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Reject Batch Items After Shutdown

## Goal

Make `Batcher.Add` report rejection once shutdown starts so it never claims an
item was accepted after the only consumer has exited.

## What to do

1. Add synchronized lifecycle state around the non-blocking intake operation.
2. Mark intake stopped before the cancellation drain begins.
3. Preserve all items accepted before that transition in the final drain.

## Tests

- Cancel, wait for `Run`, then assert `Add` returns false.
- Race producers against cancellation and assert accepted count equals flushed count.

## Boundaries

- Keep `Add` non-blocking apart from short in-memory synchronization.
- Do not make `Run` reusable.

