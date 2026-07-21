---
title: Make cached token info usable by JWT authentication
status: complete
track: foundations
depends_on: []
affects:
  - authkit/jwt.go
  - authkit/jwt_test.go
  - authkit/tokeninfo.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Make Cached Token Info Usable by JWT Authentication

## Goal

Replace the concrete token-info dependency with the minimal lookup contract so
the documented cached implementation can be used for read-tier authentication.

## What to do

1. Define an exported `TokenInfoLookup` interface beside `TokenInfo`.
2. Type `JWT.TokenInfo` and `NewJWT` against that interface.
3. Add compile-time implementation assertions for direct and cached clients.

## Tests

- Authenticate the same strict token twice through `CachedTokenInfo` and assert one upstream lookup.

## Boundaries

- Do not change cache policy or strict-token authorization fields.

## Implementation Notes

### Status

Complete in `ce91fd6` on 2026-07-21.

### What Was Done

- Added the minimal lookup interface, implementation assertions, and cache test.

### Decisions Made During Implementation

- Changed only the dependency type; cache policy and authorization stayed intact.

### Follow-ups

None.
