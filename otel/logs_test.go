package otel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

func otlpLogServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestSetupLogs_NoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	var buf bytes.Buffer
	stdout := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Replica:     "rep-0",
		Stdout:      stdout,
	})
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if logger == nil {
		t.Fatal("logger is nil")
	}
	logger.Info("hello", "k", "v")
	out := buf.String()
	if !strings.Contains(out, `"service":"svc"`) || !strings.Contains(out, `"version":"v1"`) || !strings.Contains(out, `"replica":"rep-0"`) {
		t.Errorf("base attrs not attached: %s", out)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Errorf("output is not JSON: %v", err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown err = %v", err)
	}
}

func TestSetupLogs_DefaultStdoutAndScope(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if logger == nil {
		t.Fatal("nil logger")
	}
	_ = shutdown(context.Background())
}

func TestSetupLogs_NoEndpoint_OmitsReplicaWhenEmpty(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	var buf bytes.Buffer
	stdout := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger, _, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      stdout,
	})
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("ping")
	if strings.Contains(buf.String(), "replica") {
		t.Errorf("replica attr should not appear when empty: %s", buf.String())
	}
}

func TestSetupLogs_WithEndpoint(t *testing.T) {
	srv := otlpLogServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	var buf bytes.Buffer
	stdout := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      stdout,
	})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	logger.Info("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("stdout did not see record: %s", buf.String())
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown err = %v", err)
	}
}

func TestSetupLogs_ExporterError_FallsBackToStdout(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	orig := newLogExporter
	t.Cleanup(func() { newLogExporter = orig })
	newLogExporter = func(ctx context.Context, endpoint string) (sdklog.Exporter, error) {
		return nil, errors.New("injected exporter failure")
	}
	var buf bytes.Buffer
	stdout := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger, shutdown, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      stdout,
	})
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	logger.Info("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("fallback logger did not write: %s", buf.String())
	}
	if err := shutdown(context.Background()); err != nil {
		t.Errorf("shutdown err = %v", err)
	}
}

func TestSetupLogs_ResourceError_FallsBackToStdout(t *testing.T) {
	srv := otlpLogServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	orig := newLogResource
	t.Cleanup(func() { newLogResource = orig })
	newLogResource = func(ctx context.Context, name, version string) (*resource.Resource, error) {
		return nil, errors.New("injected resource failure")
	}
	var buf bytes.Buffer
	stdout := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	logger, _, err := SetupLogs(context.Background(), LogsConfig{
		ServiceName: "svc",
		Version:     "v1",
		Stdout:      stdout,
	})
	if err == nil {
		t.Errorf("expected error, got nil")
	}
	logger.Info("hello")
	if !strings.Contains(buf.String(), "hello") {
		t.Errorf("fallback logger did not write: %s", buf.String())
	}
}

func TestStripScheme(t *testing.T) {
	cases := map[string]string{
		"http://x:1":  "x:1",
		"https://x:1": "x:1",
		"x:1":         "x:1",
		"":            "",
		"http://":     "http://",
		"https://":    "https://",
	}
	for in, want := range cases {
		if got := stripScheme(in); got != want {
			t.Errorf("stripScheme(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNoopShutdown(t *testing.T) {
	if err := noopShutdown(context.Background()); err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

// captureHandler stores records so we can verify tee semantics.
type captureHandler struct {
	level   slog.Level
	enabled bool
	records []string
}

func (c *captureHandler) Enabled(_ context.Context, l slog.Level) bool {
	if !c.enabled {
		return false
	}
	return l >= c.level
}

func (c *captureHandler) Handle(_ context.Context, r slog.Record) error {
	c.records = append(c.records, r.Message)
	return nil
}

func (c *captureHandler) WithAttrs(_ []slog.Attr) slog.Handler { out := *c; return &out }
func (c *captureHandler) WithGroup(_ string) slog.Handler      { out := *c; return &out }

func TestTeeHandler_Fanout(t *testing.T) {
	a := &captureHandler{enabled: true, level: slog.LevelInfo}
	b := &captureHandler{enabled: true, level: slog.LevelInfo}
	tee := teeHandler{primary: a, secondary: b}

	if !tee.Enabled(context.Background(), slog.LevelInfo) {
		t.Fatal("tee should be enabled when both children are")
	}
	slog.New(tee).Info("hello")
	if len(a.records) != 1 || len(b.records) != 1 {
		t.Fatalf("a=%d b=%d", len(a.records), len(b.records))
	}
}

func TestTeeHandler_EnabledWhenEitherIs(t *testing.T) {
	a := &captureHandler{enabled: true, level: slog.LevelDebug}
	b := &captureHandler{enabled: false}
	tee := teeHandler{primary: a, secondary: b}
	if !tee.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("tee should enable when primary is enabled")
	}
	a2 := &captureHandler{enabled: false}
	b2 := &captureHandler{enabled: true, level: slog.LevelDebug}
	tee2 := teeHandler{primary: a2, secondary: b2}
	if !tee2.Enabled(context.Background(), slog.LevelDebug) {
		t.Fatal("tee should enable when secondary is enabled")
	}
}

func TestTeeHandler_SkipsDisabledChild(t *testing.T) {
	a := &captureHandler{enabled: true, level: slog.LevelInfo}
	b := &captureHandler{enabled: false}
	tee := teeHandler{primary: a, secondary: b}
	slog.New(tee).Info("hi")
	if len(a.records) != 1 {
		t.Fatalf("a got %d records", len(a.records))
	}
	if len(b.records) != 0 {
		t.Fatalf("b got %d records, want 0 (disabled)", len(b.records))
	}

	a2 := &captureHandler{enabled: false}
	b2 := &captureHandler{enabled: true, level: slog.LevelInfo}
	tee2 := teeHandler{primary: a2, secondary: b2}
	slog.New(tee2).Info("hi")
	if len(a2.records) != 0 {
		t.Fatalf("a2 disabled but got %d records", len(a2.records))
	}
	if len(b2.records) != 1 {
		t.Fatalf("b2 got %d records, want 1", len(b2.records))
	}
}

func TestTeeHandler_WithAttrsAndGroup(t *testing.T) {
	a := &captureHandler{enabled: true, level: slog.LevelInfo}
	b := &captureHandler{enabled: true, level: slog.LevelInfo}
	tee := teeHandler{primary: a, secondary: b}
	if _, ok := tee.WithAttrs([]slog.Attr{slog.String("k", "v")}).(teeHandler); !ok {
		t.Errorf("WithAttrs should return teeHandler")
	}
	if _, ok := tee.WithGroup("grp").(teeHandler); !ok {
		t.Errorf("WithGroup should return teeHandler")
	}
}

func TestLoggerWithEmptyAttrs(t *testing.T) {
	var buf bytes.Buffer
	h := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	l := loggerWith(h, nil)
	l.Info("ping")
	if !strings.Contains(buf.String(), `"msg":"ping"`) {
		t.Errorf("output did not include message: %s", buf.String())
	}
}

func FuzzStripScheme(f *testing.F) {
	f.Add("http://host:1234")
	f.Add("https://host:1234")
	f.Add("host:1234")
	f.Add("")
	f.Add("http://")
	f.Fuzz(func(t *testing.T, s string) {
		got := stripScheme(s)
		if strings.HasPrefix(got, "http://") || strings.HasPrefix(got, "https://") {
			if got != s {
				t.Errorf("stripScheme(%q) = %q still has scheme prefix", s, got)
			}
		}
	})
}
