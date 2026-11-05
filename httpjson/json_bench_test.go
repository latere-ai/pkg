// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package httpjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type benchTask struct {
	ID        string            `json:"id"`
	OrgID     string            `json:"org_id"`
	Title     string            `json:"title"`
	Prompt    string            `json:"prompt"`
	Status    string            `json:"status"`
	Labels    []string          `json:"labels"`
	Env       map[string]string `json:"env,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
	Cost      float64           `json:"cost_usd"`
	Turns     int               `json:"turns"`
}

type benchListResponse struct {
	Items      []benchTask `json:"items"`
	NextCursor string      `json:"next_cursor"`
	Total      int         `json:"total"`
}

func benchTasks(n int) benchListResponse {
	base := time.Date(2026, 10, 14, 9, 30, 0, 0, time.UTC)
	out := benchListResponse{NextCursor: "c_01HZX3K9Q2M8", Total: n * 4}
	for i := range n {
		out.Items = append(out.Items, benchTask{
			ID:        fmt.Sprintf("tsk_01HZX3K9Q2M8%04d", i),
			OrgID:     "org_01HZX0000000000001",
			Title:     fmt.Sprintf("Investigate flaky readiness probe on replica %d", i),
			Prompt:    "Look at the last three deploys of the gateway, find out why the readiness probe flaps, and propose a fix with a test.",
			Status:    "running",
			Labels:    []string{"infra", "gateway", "p2"},
			Env:       map[string]string{"REGION": "fra1", "TIER": "prod"},
			CreatedAt: base.Add(time.Duration(i) * time.Minute),
			Cost:      0.4213 + float64(i)/1000,
			Turns:     12 + i%7,
		})
	}
	return out
}

var benchBodySizes = []struct {
	name  string
	items int
}{{"small", 1}, {"medium", 22}, {"large", 430}}

// benchWriter is a ResponseWriter that discards the body.
type benchWriter struct {
	h    http.Header
	code int
}

func (w *benchWriter) Header() http.Header         { return w.h }
func (w *benchWriter) WriteHeader(c int)           { w.code = c }
func (w *benchWriter) Write(p []byte) (int, error) { return len(p), nil }

// BenchmarkJSONWriteEncode is every JSON API response a service writes
// through Write: a paginated listing of task records.
func BenchmarkJSONWriteEncode(b *testing.B) {
	prev := slog.SetLogLoggerLevel(slog.LevelError + 8)
	b.Cleanup(func() { slog.SetLogLoggerLevel(prev) })
	for _, sz := range benchBodySizes {
		b.Run(sz.name, func(b *testing.B) {
			v := benchTasks(sz.items)
			enc, err := json.Marshal(v)
			if err != nil {
				b.Fatal(err)
			}
			w := &benchWriter{h: http.Header{}}
			b.ReportAllocs()
			b.SetBytes(int64(len(enc) + 1))
			for b.Loop() {
				Write(w, http.StatusOK, v)
				if w.code != http.StatusOK {
					b.Fatalf("status %d", w.code)
				}
			}
		})
	}
}

// BenchmarkJSONDecodeBodyDecode is every strict JSON request body a handler
// reads through DecodeBody.
func BenchmarkJSONDecodeBodyDecode(b *testing.B) {
	for _, sz := range benchBodySizes {
		b.Run(sz.name, func(b *testing.B) {
			body, err := json.Marshal(benchTasks(sz.items))
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			for b.Loop() {
				r := httptest.NewRequest(http.MethodPost, "/api/tasks", bytes.NewReader(body))
				w := &benchWriter{h: http.Header{}}
				v, ok := DecodeBody[benchListResponse](w, r)
				if !ok || len(v.Items) != sz.items {
					b.Fatalf("decode failed: ok=%v status=%d", ok, w.code)
				}
			}
		})
	}
}

// BenchmarkJSONDecodeOptionalBodyDecode is the handler path for endpoints
// whose body is optional (action endpoints with a small options object).
func BenchmarkJSONDecodeOptionalBodyDecode(b *testing.B) {
	body := []byte(`{"id":"tsk_01HZX3K9Q2M80001","org_id":"org_01HZX0000000000001","title":"Retry","prompt":"Run it again with verbose logging.","status":"queued","labels":["infra"],"created_at":"2026-10-14T09:30:00Z","cost_usd":0,"turns":0}`)
	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	for b.Loop() {
		r := httptest.NewRequest(http.MethodPost, "/api/tasks/x/retry", io.NopCloser(bytes.NewReader(body)))
		w := &benchWriter{h: http.Header{}}
		if _, ok := DecodeOptionalBody[benchTask](w, r); !ok {
			b.Fatalf("decode failed: status %d", w.code)
		}
	}
}
