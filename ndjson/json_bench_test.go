// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ndjson

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type benchEntry struct {
	Seq       int             `json:"seq"`
	TS        time.Time       `json:"ts"`
	Role      string          `json:"role"`
	Text      string          `json:"text"`
	ToolName  string          `json:"tool_name,omitempty"`
	ToolInput json.RawMessage `json:"tool_input,omitempty"`
	Tokens    int             `json:"tokens"`
}

func benchEntries(n int) []benchEntry {
	base := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	text := strings.Repeat("Checked the readiness probe configuration and the pool settings. ", 3)
	out := make([]benchEntry, n)
	for i := range out {
		e := benchEntry{Seq: i, TS: base.Add(time.Duration(i) * 7 * time.Second), Role: "assistant", Text: text, Tokens: 180 + i%40}
		if i%3 == 0 {
			e.ToolName = "read_file"
			e.ToolInput = json.RawMessage(`{"path":"internal/svc/handler.go","limit":200}`)
		}
		out[i] = e
	}
	return out
}

func benchFile(b *testing.B, n int) (string, int64) {
	b.Helper()
	var sb strings.Builder
	for _, e := range benchEntries(n) {
		line, err := json.Marshal(e)
		if err != nil {
			b.Fatal(err)
		}
		sb.Write(line)
		sb.WriteByte('\n')
	}
	path := filepath.Join(b.TempDir(), "transcript.ndjson")
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	return path, int64(sb.Len())
}

// BenchmarkJSONReadFileDecode is a service loading a persisted transcript
// or event log from an NDJSON file.
func BenchmarkJSONReadFileDecode(b *testing.B) {
	for _, sz := range []struct {
		name string
		n    int
	}{{"small", 3}, {"medium", 45}, {"large", 900}} {
		b.Run(sz.name, func(b *testing.B) {
			path, size := benchFile(b, sz.n)
			b.ReportAllocs()
			b.SetBytes(size)
			for b.Loop() {
				got, err := ReadFile[benchEntry](path, WithBufferSize(64*1024, 1<<20))
				if err != nil {
					b.Fatal(err)
				}
				if len(got) != sz.n {
					b.Fatalf("read %d entries, want %d", len(got), sz.n)
				}
			}
		})
	}
}

// BenchmarkJSONAppendFileEncode is a service appending one record to a
// persisted transcript.
func BenchmarkJSONAppendFileEncode(b *testing.B) {
	rec := benchEntries(1)[0]
	enc, err := json.Marshal(rec)
	if err != nil {
		b.Fatal(err)
	}
	path := filepath.Join(b.TempDir(), "append.ndjson")
	b.ReportAllocs()
	b.SetBytes(int64(len(enc) + 1))
	for b.Loop() {
		if err := AppendFile(path, rec); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkJSONPreferResultLineDecode is the agent-output parser that scans
// an NDJSON stream for the terminal result line, newest line first.
func BenchmarkJSONPreferResultLineDecode(b *testing.B) {
	type line struct {
		Type       string `json:"type"`
		Subtype    string `json:"subtype,omitempty"`
		Text       string `json:"text,omitempty"`
		StopReason string `json:"stop_reason,omitempty"`
		NumTurns   int    `json:"num_turns,omitempty"`
	}
	var sb strings.Builder
	for i := range 60 {
		fmt.Fprintf(&sb, `{"type":"assistant","text":"Working through step %d of the migration plan and checking the result."}`+"\n", i)
	}
	sb.WriteString(`{"type":"result","subtype":"success","text":"Done.","stop_reason":"end_turn","num_turns":61}` + "\n")
	raw := sb.String()
	b.ReportAllocs()
	b.SetBytes(int64(len(raw)))
	for b.Loop() {
		got, ok := PreferResultLine[line](raw, true,
			func(l *line) bool { return l.Type == "result" },
			func(l *line) bool { return l.StopReason != "" })
		if !ok || got.NumTurns != 61 {
			b.Fatal("result line not found")
		}
	}
}
