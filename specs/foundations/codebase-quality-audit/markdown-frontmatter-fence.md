---
title: Preserve indented YAML block content
status: validated
track: foundations
depends_on: []
affects:
  - md/md.go
  - md/md_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Preserve Indented YAML Block Content

## Goal

Recognize a closing frontmatter fence only at column one so indented `---` lines
inside YAML block scalars remain data.

## What to do

1. Match `---` at column one with optional trailing horizontal whitespace.
2. Preserve the current opening-fence and unclosed-document behavior.
3. Correct the test that currently blesses indented closing fences.

## Tests

- Parse a YAML literal containing an indented `---` and assert the full value/body.
- Retain coverage for a column-one fence with trailing whitespace.

## Boundaries

- Do not add a new YAML parser or change leading-newline handling.

