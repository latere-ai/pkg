---
title: Spec document model
status: complete
track: local
depends_on: []
affects:
  - specs/
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Spec Document Model

Every spec is a Markdown document with YAML frontmatter. A parent spec has a
sibling directory with the same base name; files in that directory are its
children. A leaf spec has no child directory and describes one implementable,
testable change.

## Frontmatter

Required fields are `title`, `status`, `track`, `depends_on`, `affects`,
`effort`, `created`, `updated`, `author`, and `dispatched_task_id`.

- `status`: `vague`, `drafted`, `validated`, `complete`, `stale`, or `archived`
- `track`: the first directory below `specs/`
- `effort`: `small`, `medium`, `large`, or `xlarge`
- `depends_on`: repository-relative spec paths forming an acyclic graph
- `affects`: repository-relative files or directories governed by the spec
- `dispatched_task_id`: `null` unless a leaf is dispatched externally

Dates use `YYYY-MM-DD`, and `updated` cannot precede `created`. A complete
parent must have only complete leaves in its subtree.

## Leaf Specs

A validated implementation task contains `Goal`, `What to do`, `Tests`, and
`Boundaries` sections. It should fit in one focused commit, leave the repository
passing, and name the exact behavior its regression tests protect.
