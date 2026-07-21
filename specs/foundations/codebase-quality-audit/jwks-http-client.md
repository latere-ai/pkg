---
title: Honor custom HTTP clients for JWKS
status: complete
track: foundations
depends_on: []
affects:
  - jwtauth/jwtauth.go
  - jwtauth/jwtauth_test.go
  - oidclogin/oidclogin.go
  - oidclogin/oidclogin_test.go
effort: medium
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Honor Custom HTTP Clients for JWKS

## Goal

Use the caller's HTTP transport for both OIDC discovery and JWKS retrieval so
private trust roots, proxies, and mTLS policies are not bypassed.

## What to do

1. Add an optional `HTTPClient` to `jwtauth.Config` with the existing timeout client as default.
2. Store the fetch function on each JWKS cache while retaining the existing test seam for default clients.
3. Pass `oidclogin.Config.HTTPClient` to both ID-token and access-token validators.

## Tests

- Verify a token from a TLS test issuer succeeds only through its supplied client.
- Keep default JWKS caching and forced-refresh tests passing.

## Boundaries

- Do not expand supported JWT algorithms or alter cache semantics.

## Implementation Notes

### Status

Complete in `2aebf5b` on 2026-07-21.

### What Was Done

- Wired caller transports through JWKS caches and both OIDC token validators.
- Added TLS issuer regressions while preserving default cache tests.

### Decisions Made During Implementation

- Stored fetch behavior per cache and retained the global default-client seam.

### Follow-ups

None.
