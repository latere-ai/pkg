package otel

import (
	"context"
	"log/slog"
	"os"
	"strings"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/log/global"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// LogsConfig configures SetupLogs.
type LogsConfig struct {
	// ServiceName labels every emitted record. Required.
	ServiceName string
	// Version labels every emitted record. Required.
	Version string
	// Replica labels every emitted record (e.g. Pod name). Optional.
	Replica string
	// Level is the slog level. Defaults to slog.LevelInfo.
	Level slog.Level
	// Stdout, when non-nil, is used as the local handler that runs alongside
	// the OTLP bridge. Defaults to a JSON handler on os.Stderr at Level.
	Stdout slog.Handler
	// Scope is the otelslog instrumentation scope. Defaults to ServiceName.
	Scope string
}

var (
	newLogExporter = func(ctx context.Context, endpoint string) (sdklog.Exporter, error) {
		opts := []otlploghttp.Option{otlploghttp.WithEndpoint(stripScheme(endpoint))}
		// Honor the endpoint scheme like the trace/metric exporters instead of
		// always forcing plaintext: an https:// endpoint keeps TLS. Only an
		// explicit http:// (or scheme-less) endpoint stays insecure, so this
		// cannot break a plaintext in-cluster collector while it fixes silent
		// log loss against a TLS gateway.
		if useInsecure(endpoint) {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		return otlploghttp.New(ctx, opts...)
	}
	// newLogResource shares serviceResource so log records carry the same
	// service + deployment.environment attributes as traces and metrics.
	newLogResource = serviceResource
)

// SetupLogs returns a logger that fans records into a local slog handler
// (defaulting to JSON on stderr) plus an OTLP otelslog bridge when
// OTEL_EXPORTER_OTLP_ENDPOINT is set. The shutdown function flushes pending
// log records and is safe to call when the OTLP path was never installed.
//
// Errors from the OTLP path do not mask the local handler: if the exporter
// fails to initialise, SetupLogs returns the local-only logger and a noop
// shutdown along with the underlying error so callers may decide whether to
// log it. Errors from emitting a record on the OTLP bridge are silently
// dropped at write time so the local writer remains the source of truth for
// ops.
func SetupLogs(ctx context.Context, cfg LogsConfig) (*slog.Logger, func(context.Context) error, error) {
	if cfg.Stdout == nil {
		cfg.Stdout = slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.Level})
	}
	if cfg.Scope == "" {
		cfg.Scope = cfg.ServiceName
	}

	base := []slog.Attr{
		slog.String("service", cfg.ServiceName),
		slog.String("version", cfg.Version),
	}
	if cfg.Replica != "" {
		base = append(base, slog.String("replica", cfg.Replica))
	}

	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		return loggerWith(cfg.Stdout, base), noopShutdown, nil
	}

	exp, err := newLogExporter(ctx, endpoint)
	if err != nil {
		return loggerWith(cfg.Stdout, base), noopShutdown, err
	}
	res, err := newLogResource(ctx, cfg.ServiceName, cfg.Version)
	if err != nil {
		// The exporter was constructed successfully; reclaim it (it holds an
		// http client) before falling back to the local-only logger.
		_ = exp.Shutdown(ctx)
		return loggerWith(cfg.Stdout, base), noopShutdown, err
	}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
		sdklog.WithResource(res),
	)
	global.SetLoggerProvider(provider)

	bridge := otelslog.NewHandler(cfg.Scope, otelslog.WithLoggerProvider(provider))
	tee := teeHandler{primary: cfg.Stdout, secondary: bridge}
	return loggerWith(tee, base), provider.Shutdown, nil
}

func loggerWith(h slog.Handler, attrs []slog.Attr) *slog.Logger {
	a := make([]any, 0, len(attrs))
	for _, kv := range attrs {
		a = append(a, kv)
	}
	return slog.New(h).With(a...)
}

func noopShutdown(context.Context) error { return nil }

// useInsecure reports whether the log exporter should force a plaintext
// connection to endpoint. Only an explicit https:// endpoint keeps TLS;
// http:// and scheme-less endpoints stay insecure, preserving the historical
// plaintext behavior for in-cluster collectors.
func useInsecure(endpoint string) bool {
	return !strings.HasPrefix(endpoint, "https://")
}

// stripScheme drops a leading http:// or https:// from s. The OTLP/HTTP
// exporter accepts the bare authority (host:port) and rejects the scheme.
func stripScheme(s string) string {
	for _, p := range []string{"http://", "https://"} {
		if strings.HasPrefix(s, p) && len(s) > len(p) {
			return s[len(p):]
		}
	}
	return s
}

// teeHandler fans every log record to two handlers. The secondary's errors do
// not propagate; the primary is the source of truth for ops.
type teeHandler struct {
	primary, secondary slog.Handler
}

func (t teeHandler) Enabled(ctx context.Context, l slog.Level) bool {
	return t.primary.Enabled(ctx, l) || t.secondary.Enabled(ctx, l)
}

func (t teeHandler) Handle(ctx context.Context, r slog.Record) error {
	if t.secondary.Enabled(ctx, r.Level) {
		_ = t.secondary.Handle(ctx, r.Clone())
	}
	if t.primary.Enabled(ctx, r.Level) {
		return t.primary.Handle(ctx, r)
	}
	return nil
}

func (t teeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return teeHandler{
		primary:   t.primary.WithAttrs(attrs),
		secondary: t.secondary.WithAttrs(attrs),
	}
}

func (t teeHandler) WithGroup(name string) slog.Handler {
	return teeHandler{
		primary:   t.primary.WithGroup(name),
		secondary: t.secondary.WithGroup(name),
	}
}
