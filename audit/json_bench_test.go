// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"
)

func benchAuditPayload(items int) json.RawMessage {
	list := make([]map[string]any, items)
	for i := range list {
		list[i] = map[string]any{
			"path":   fmt.Sprintf("/workspace/internal/svc/handler_%d.go", i),
			"bytes":  4096 + i,
			"note":   "request carried Authorization: Bearer abcdefghijklmnop0123456789",
			"labels": []string{"exec", "sandbox"},
		}
	}
	p, _ := json.Marshal(map[string]any{
		"command":   "go test ./...",
		"exit_code": 0,
		"snowflake": int64(1790000000000000123),
		"files":     list,
	})
	return p
}

func benchAuditEvent(items int) Event {
	return Event{
		EventID:   "evt_01HZX3K9Q2M8N4",
		TS:        time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC),
		Category:  CategoryExec,
		Actor:     Actor{Type: "user", PrincipalID: "usr_01HZX0000000000001", OwnerSub: "sub|8f3a"},
		Replica:   "sandboxd-7c9d4",
		RequestID: "req_01HZX3K9Q2M8N4",
		OrgID:     "org_01HZX0000000000001",
		Subject:   &Subject{Kind: "sandbox", ID: "sbx_01HZX3K9Q2", Name: "build-runner"},
		Policy:    "exec.allow.default",
		Payload:   benchAuditPayload(items),
	}
}

var benchAuditSizes = []struct {
	name  string
	items int
}{{"small", 3}, {"medium", 60}, {"large", 1200}}

// BenchmarkJSONStdoutEmitEncode is the audit emitter serializing one event
// as an NDJSON line.
func BenchmarkJSONStdoutEmitEncode(b *testing.B) {
	ctx := context.Background()
	for _, sz := range benchAuditSizes {
		b.Run(sz.name, func(b *testing.B) {
			ev := benchAuditEvent(sz.items)
			enc, err := json.Marshal(ev)
			if err != nil {
				b.Fatal(err)
			}
			em := NewStdoutEmitter(io.Discard)
			b.ReportAllocs()
			b.SetBytes(int64(len(enc) + 1))
			for b.Loop() {
				if err := em.Emit(ctx, ev); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkJSONRedactJSONRoundTrip is the scrubber that decodes an audit
// payload, redacts credential-shaped values and re-encodes it.
func BenchmarkJSONRedactJSONRoundTrip(b *testing.B) {
	// The scrubber runs a set of regular expressions over every string, so
	// it is used on payloads up to the medium class only.
	for _, sz := range benchAuditSizes[:2] {
		b.Run(sz.name, func(b *testing.B) {
			payload := benchAuditPayload(sz.items)
			b.ReportAllocs()
			b.SetBytes(int64(len(payload)))
			for b.Loop() {
				if out := RedactJSON(payload); len(out) == 0 {
					b.Fatal("empty output")
				}
			}
		})
	}
}
