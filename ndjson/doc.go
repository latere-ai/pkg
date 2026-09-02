// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package ndjson provides reading and appending for newline-delimited JSON
// (NDJSON/JSONL) files, the format for event-sourcing traces and usage records
// where each line is a self-contained JSON object.
//
// [ReadFile] consolidates the open-scan-unmarshal loop into one generic call,
// and [AppendFile] appends a record atomically so concurrent writers do not
// interleave. Missing files are treated as empty rather than as errors.
//
// # Usage
//
//	events, err := ndjson.ReadFile[Event](tracePath)
//	err = ndjson.AppendFile(tracePath, newEvent)
package ndjson
