---
title: Validate cookie sessions before authentication
status: complete
track: foundations
depends_on: []
affects:
  - authkit/session.go
  - authkit/session_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Validate Cookie Sessions Before Authentication

## Goal

Reject replayed or empty encrypted sessions and retain organization roles when
building an authenticated identity.

## What to do

1. Reject sessions without a subject.
2. Reject elapsed access-token or dashboard-session expiries when present.
3. Copy `User.OrgRoles` into `Identity.Roles`.

## Tests

- Assert a valid session carries organization roles.
- Table-test empty subject, expired token, and expired session window.

## Boundaries

- Do not refresh tokens or change cookie encryption in this adapter.
- Preserve a zero optional dashboard-session expiry for legacy sessions; a
  missing access-token expiry remains invalid.

## Implementation Notes

### Status

Complete in `6b350a3` on 2026-07-21.

### What Was Done

- Rejected empty subjects and invalid lifetimes, and preserved organization roles.

### Decisions Made During Implementation

- Required access-token expiry but allowed a missing optional session expiry.

### Follow-ups

None.
