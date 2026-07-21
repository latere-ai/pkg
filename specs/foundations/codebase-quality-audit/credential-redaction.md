---
title: Redact quoted and fine-grained credentials
status: validated
track: foundations
depends_on: []
affects:
  - audit/redact.go
  - audit/audit_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Redact Quoted and Fine-Grained Credentials

## Goal

Prevent quoted shell assignments and GitHub fine-grained tokens from leaking
through the audit redactor despite its documented credential coverage.

## What to do

1. Extend assignment redaction to preserve optional matching quotes while
   replacing only the credential value.
2. Add the `github_pat_` token family to the credential rules.
3. Keep benign surrounding text unchanged.

## Tests

- Add table cases for single-quoted and double-quoted `API_TOKEN` assignments.
- Add a realistic `github_pat_` value and assert the original secret is absent.

## Boundaries

- Do not change JSON key redaction or broaden unrelated credential-key suffixes.

