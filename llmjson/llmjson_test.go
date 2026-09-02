// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package llmjson

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestUnfence(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "no fence", in: `{"a":1}`, want: `{"a":1}`},
		{name: "surrounding whitespace", in: "\n  {\"a\":1}\n ", want: `{"a":1}`},
		{name: "json tag", in: "```json\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "uppercase tag", in: "```JSON\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "bare fence", in: "```\n{\"a\":1}\n```", want: `{"a":1}`},
		{name: "prose after the fence is dropped", in: "```json\n{\"a\":1}\n```\nHope this helps!", want: `{"a":1}`},
		{name: "opening fence with no newline", in: "```", want: ""},
		{name: "unclosed fence", in: "```json\n{\"a\":1}", want: `{"a":1}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Unfence(tt.in); got != tt.want {
				t.Fatalf("Unfence(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestUnfenceLeavesInnerFence covers the boundary: a fence inside a string
// value is content. Removing it would corrupt the answer, not repair it.
func TestUnfenceLeavesInnerFence(t *testing.T) {
	in := "```json\n{\"code\":\"```go\\nfmt.Println()\\n```\"}\n```"
	got := Unfence(in)
	if !strings.Contains(got, "```go") {
		t.Fatalf("Unfence(%q) = %q, want the inner fence kept", in, got)
	}
	var out struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal([]byte(got), &out); err != nil {
		t.Fatalf("result is not valid JSON: %v", err)
	}
}

func TestEscapeControls(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "raw newline inside a value",
			in:   "{\"a\":\"one\ntwo\"}",
			want: `{"a":"one\ntwo"}`,
		},
		{
			name: "raw tab inside a value",
			in:   "{\"a\":\"one\ttwo\"}",
			want: `{"a":"one\ttwo"}`,
		},
		{
			name: "carriage return inside a value",
			in:   "{\"a\":\"one\rtwo\"}",
			want: `{"a":"one\rtwo"}`,
		},
		{
			name: "layout outside strings is untouched",
			in:   "{\n\t\"a\": 1\n}",
			want: "{\n\t\"a\": 1\n}",
		},
		{
			name: "an existing escape is not doubled",
			in:   `{"a":"one\ntwo"}`,
			want: `{"a":"one\ntwo"}`,
		},
		{
			name: "an escaped quote does not end the string",
			in:   "{\"a\":\"say \\\"hi\\\"\nnow\"}",
			want: `{"a":"say \"hi\"\nnow"}`,
		},
		{
			name: "a trailing backslash does not read past the end",
			in:   `{"a":"x\`,
			want: `{"a":"x\`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EscapeControls(tt.in); got != tt.want {
				t.Fatalf("EscapeControls(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestRepairMakesModelOutputDecodable is the case the package exists for: a
// fenced, pretty-printed reply whose multi-line values carry raw newlines.
func TestRepairMakesModelOutputDecodable(t *testing.T) {
	raw := "```json\n{\n  \"lang\": \"en\",\n  \"title\": \"A Title\",\n  \"content\": \"Line one.\n\nLine two.\"\n}\n```"

	var before map[string]string
	if err := json.Unmarshal([]byte(raw), &before); err == nil {
		t.Fatal("the raw reply decoded, so this input no longer covers the case")
	}

	var after map[string]string
	if err := json.Unmarshal([]byte(Repair(raw)), &after); err != nil {
		t.Fatalf("Repair() output does not decode: %v", err)
	}
	if after["content"] != "Line one.\n\nLine two." {
		t.Fatalf("content = %q, want the paragraph break preserved", after["content"])
	}
	if after["lang"] != "en" || after["title"] != "A Title" {
		t.Fatalf("decoded = %v", after)
	}
}

// TestRepairLeavesValidJSONAlone keeps the repair from being a rewrite: a
// reply that was already correct must survive it unchanged.
func TestRepairLeavesValidJSONAlone(t *testing.T) {
	for _, in := range []string{
		`{"a":"one\ntwo","b":2}`,
		`{"a":[1,2,{"b":null}],"c":true}`,
		`{"unicode":"标题","escaped":"é"}`,
	} {
		t.Run(in, func(t *testing.T) {
			if got := Repair(in); got != in {
				t.Fatalf("Repair(%q) = %q, want it unchanged", in, got)
			}
		})
	}
}

// FuzzRepair asserts the two properties that matter for a repair step: it
// never panics, and it never turns valid JSON into invalid JSON.
func FuzzRepair(f *testing.F) {
	for _, s := range []string{
		`{"a":1}`, "{\"a\":\"x\ny\"}", "```json\n{}\n```", `{"a":"\`, ``, `"`, `[1,2]`,
		`{"a":"A"}`, "{\"a\":\"\t\"}",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Repair(s)
		if !utf8.ValidString(s) {
			return
		}
		if !utf8.ValidString(got) {
			t.Fatalf("Repair(%q) produced invalid UTF-8: %q", s, got)
		}
		var v any
		if json.Unmarshal([]byte(s), &v) != nil {
			return
		}
		// Valid JSON in must stay valid JSON out. A repair that breaks a
		// correct reply is worse than no repair.
		var w any
		if err := json.Unmarshal([]byte(got), &w); err != nil {
			t.Fatalf("Repair(%q) = %q, which no longer decodes: %v", s, got, err)
		}
	})
}
