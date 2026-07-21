---
title: Report migration close errors
status: validated
track: foundations
depends_on: []
affects:
  - pgxmigrate/pgxmigrate.go
  - pgxmigrate/pgxmigrate_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Report Migration Close Errors

## Goal

Return source and database close failures instead of silently reporting a clean
migration startup.

## What to do

1. Capture both errors returned by `migrator.Close`.
2. Join wrapped migration, source-close, and database-close errors.
3. Preserve `migrate.ErrNoChange` as success when cleanup succeeds.

## Tests

- Assert source and database close errors are discoverable with `errors.Is`.
- Assert an Up error remains discoverable when Close also fails.

## Boundaries

- Do not retry migrations or change database-driver selection.

