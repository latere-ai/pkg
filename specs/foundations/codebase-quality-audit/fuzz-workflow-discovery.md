---
title: Discover fuzz targets in one workflow
status: complete
track: foundations
depends_on: []
affects:
  - Makefile
  - .github/workflows/ci.yml
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Discover Fuzz Targets in One Workflow

## Goal

Eliminate stale duplicated fuzz manifests by discovering every repository
`Fuzz*` target from the Go test tree and making CI call that one target.

## What to do

1. Replace the manual Makefile list with package/target discovery.
2. Support a configurable fuzz duration while keeping 30 seconds as default.
3. Replace CI's copied list with `make fuzz`.

## Tests

- Run every discovered target for one iteration as an end-to-end workflow check.

## Boundaries

- Do not change ordinary race or coverage gates.

## Implementation Notes

### Status

Complete in `d166d44` on 2026-07-21.

### What Was Done

- Made the test tree the fuzz manifest and routed CI through `make fuzz`.
- Verified all 20 current targets with one iteration each.

### Decisions Made During Implementation

- Kept the 30-second default while allowing `FUZZTIME` and `GO` overrides.

### Follow-ups

None.
