// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ndjson

import (
	"encoding/json"
	"strings"
	"testing"
)

type fuzzLine struct {
	Type       string `json:"type"`
	StopReason string `json:"stop_reason"`
}

// FuzzPreferResultLine feeds arbitrary text through the agent-output scanner.
// The input is whatever a harness wrote to its stream, so malformed JSON, bare
// braces, lone newlines, and invalid UTF-8 all reach it in practice.
//
// The properties held here are the ones callers depend on: the scanner never
// panics, ok is reported only when some line actually decoded into a candidate,
// and a terminal hit really is terminal. The last one is what makes the
// fallback safe to use — a caller that gets ok=true and a non-terminal record
// knows it is looking at the fallback, not a missed result line.
func FuzzPreferResultLine(f *testing.F) {
	for _, raw := range []string{
		"",
		"\n\n",
		`{"type":"result","stop_reason":"end_turn"}`,
		"{\"type\":\"assistant\"}\n{\"type\":\"result\",\"stop_reason\":\"end_turn\"}",
		"{\"type\":\"result\",\"stop_reason\":\"end_turn\"}\n{\"type\":\"debug\"}",
		"not json\n{broken\n{}",
		"{\xff}",
		"   {\"type\":\"result\",\"stop_reason\":\"\"}   ",
	} {
		for _, backward := range []bool{false, true} {
			f.Add(raw, backward)
		}
	}

	isCandidate := func(l *fuzzLine) bool { return l.Type != "debug" }
	isTerminal := func(l *fuzzLine) bool { return l.Type == "result" && l.StopReason != "" }

	f.Fuzz(func(t *testing.T, raw string, backward bool) {
		got, ok := PreferResultLine(raw, backward, isCandidate, isTerminal)

		// Independently establish whether any line could have decoded into a
		// candidate. ok must agree.
		anyCandidate := false
		for line := range strings.SplitSeq(strings.TrimSpace(raw), "\n") {
			line = strings.TrimSpace(line)
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var c fuzzLine
			if json.Unmarshal([]byte(line), &c) != nil {
				continue
			}
			if isCandidate(&c) {
				anyCandidate = true
				break
			}
		}
		if ok != anyCandidate {
			t.Fatalf("PreferResultLine(%q, %v) ok = %v, want %v", raw, backward, ok, anyCandidate)
		}
		if !ok {
			var zero fuzzLine
			if got != zero {
				t.Fatalf("PreferResultLine(%q, %v) returned %+v alongside ok=false", raw, backward, got)
			}
			return
		}
		// Whatever came back must itself have passed isCandidate, whether it is
		// the terminal line or the fallback.
		if !isCandidate(&got) {
			t.Fatalf("PreferResultLine(%q, %v) returned a non-candidate %+v", raw, backward, got)
		}
		// A terminal line, if one exists among the candidates, must win over the
		// fallback.
		terminalExists := false
		for line := range strings.SplitSeq(strings.TrimSpace(raw), "\n") {
			line = strings.TrimSpace(line)
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			var c fuzzLine
			if json.Unmarshal([]byte(line), &c) != nil {
				continue
			}
			if isCandidate(&c) && isTerminal(&c) {
				terminalExists = true
				break
			}
		}
		if terminalExists && !isTerminal(&got) {
			t.Fatalf("PreferResultLine(%q, %v) = %+v, want the terminal line", raw, backward, got)
		}
	})
}
