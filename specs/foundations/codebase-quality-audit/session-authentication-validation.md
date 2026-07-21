---
title: Validate cookie sessions before authentication
status: validated
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
- Preserve zero optional expiry fields for legacy sessions.

