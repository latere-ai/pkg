package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// decodeLines parses each newline-delimited JSON log record in buf.
func decodeLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("decode %q: %v", line, err)
		}
		out = append(out, m)
	}
	return out
}

// TestSetupLogs_LocalStreamCarriesTraceIDs is the property that makes a
// container log line actionable: read a trace_id off stdout, paste it into the
// backend, get the trace. Two services used to hand-roll this; every service
// gets it now.
func TestSetupLogs_LocalStreamCarriesTraceIDs(t *testing.T) {
	sr := installRecorder(t)
	_ = sr

	var buf bytes.Buffer
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      slog.NewJSONHandler(&buf, nil),
	})
	if err != nil {
		t.Fatalf("SetupLogs: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	// Log from inside a server span so the record's context carries one.
	h := Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		logger.InfoContext(r.Context(), "handled")
	}), "svc")
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	records := decodeLines(t, &buf)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}

	traceID, _ := records[0]["trace_id"].(string)
	if traceID == "" {
		t.Error("local record has no trace_id; kubectl logs cannot be joined to a trace")
	}
	if spanID, _ := records[0]["span_id"].(string); spanID == "" {
		t.Error("local record has no span_id")
	}
}

// TestSetupLogs_NoSpanOmitsTraceIDs keeps startup and shutdown lines clean
// rather than stamping them with empty fields.
func TestSetupLogs_NoSpanOmitsTraceIDs(t *testing.T) {
	var buf bytes.Buffer
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      slog.NewJSONHandler(&buf, nil),
	})
	if err != nil {
		t.Fatalf("SetupLogs: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	logger.Info("starting")

	records := decodeLines(t, &buf)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if _, ok := records[0]["trace_id"]; ok {
		t.Error("trace_id present on a record emitted outside any span")
	}
}

// TestSetupLogs_TraceIDsSurviveWithAttrs guards the wrapper's delegation: a
// logger derived with .With must keep stamping trace context.
func TestSetupLogs_TraceIDsSurviveWithAttrs(t *testing.T) {
	installRecorder(t)

	var buf bytes.Buffer
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      slog.NewJSONHandler(&buf, nil),
	})
	if err != nil {
		t.Fatalf("SetupLogs: %v", err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	derived := logger.With("component", "worker").WithGroup("req")

	h := Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		derived.InfoContext(r.Context(), "handled")
	}), "svc")
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/x", nil))

	records := decodeLines(t, &buf)
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	// The group applies to attributes added after it, so trace context lands
	// under "req". Assert it exists somewhere rather than pinning the shape.
	if !strings.Contains(buf.String(), "trace_id") {
		t.Error("derived logger dropped trace context")
	}
}
