---
title: Preserve OpenAI Chat user-block ordering
status: complete
track: foundations
depends_on: []
affects:
  - llmdialect/openaichat/openaichat.go
  - llmdialect/openaichat/openaichat_test.go
effort: small
created: 2026-07-21
updated: 2026-07-21
author: changkun
dispatched_task_id: null
---

# Preserve OpenAI Chat User-Block Ordering

## Goal

Encode mixed text and tool-result blocks in their original conversational order.

## What to do

1. Flush accumulated user content before emitting each tool-result message.
2. Resume a fresh user segment after the tool result.
3. Preserve the scalar optimization for a single text block.

## Tests

- Encode text, tool result, text and assert roles `user`, `tool`, `user` with exact content.

## Boundaries

- Do not alter assistant tool-call encoding or IR event grammar.

## Implementation Notes

### Status

Complete in `25d9b1d` on 2026-07-21.

### What Was Done

- Preserved text/tool/text ordering with an exact message-sequence regression.

### Decisions Made During Implementation

- Retained scalar encoding for a single text block.

### Follow-ups

None.
