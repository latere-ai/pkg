// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"runtime/debug"
	"time"
)

// readBuildInfo and lookupHostname are function-var seams so tests can drive
// the build-info and hostname fallbacks without depending on the build or host.
var (
	readBuildInfo  = debug.ReadBuildInfo
	lookupHostname = os.Hostname
)

// Config configures Bootstrap.
type Config struct {
	// ServiceName labels every span, metric, and log record. Required.
	ServiceName string
	// Version labels telemetry. When empty, Version("") derives it from build
	// info so services need not hardcode a version string.
	Version string
	// Level is the slog level. Defaults to slog.LevelInfo.
	Level slog.Level
	// Stdout, when non-nil, is the local handler that runs alongside the OTLP
	// log bridge. Defaults to a JSON handler on os.Stderr at Level.
	Stdout slog.Handler
	// Scope is the otelslog instrumentation scope. Defaults to ServiceName.
	Scope string
	// Replica labels every log record. When empty, Replica() derives it from
	// the pod name or hostname.
	Replica string
}

// Bootstrap wires the full telemetry stack in one call: structured logging
// (local handler teed to the OTLP bridge), traces, and metrics. It sets the
// returned logger as slog's default and returns a single shutdown function that
// flushes everything.
//
// When OTEL_EXPORTER_OTLP_ENDPOINT is unset, logging stays local-only and
// traces/metrics are a noop, so calling Bootstrap is safe in any environment.
//
// The returned error comes from the OTLP log path (see SetupLogs); it does not
// mask the logger, which is always usable. Callers may log it and continue.
// The returned shutdown is always non-nil and safe to call.
//
// Bootstrap deliberately does not install signal handling or wrap an
// http.Handler. Servers compose otel.Handler themselves and run via RunServer;
// workers and CLIs use Bootstrap alone.
func Bootstrap(ctx context.Context, cfg Config) (*slog.Logger, func(context.Context) error, error) {
	if cfg.Version == "" {
		cfg.Version = Version("")
	}
	if cfg.Replica == "" {
		cfg.Replica = Replica()
	}

	logger, shutdownLogs, logErr := SetupLogs(ctx, LogsConfig{
		ServiceName: cfg.ServiceName,
		Version:     cfg.Version,
		Replica:     cfg.Replica,
		Level:       cfg.Level,
		Stdout:      cfg.Stdout,
		Scope:       cfg.Scope,
	})
	slog.SetDefault(logger)

	shutdownTel := Setup(ctx, cfg.ServiceName, cfg.Version)

	shutdown := func(ctx context.Context) error {
		// Stop traces/metrics first (its own 5s budget inside Setup), then
		// flush logs last so shutdown diagnostics still reach the bridge.
		shutdownTel()
		return shutdownLogs(ctx)
	}
	return logger, shutdown, logErr
}

// Version resolves a service version string. If override is non-empty it wins.
// Otherwise it reads build info: the module version, falling back to a short
// VCS revision, and finally "dev" when nothing is embedded (e.g. `go run` or
// tests). The "(devel)" placeholder the toolchain emits is treated as unset.
func Version(override string) string {
	if override != "" {
		return override
	}
	info, ok := readBuildInfo()
	if !ok {
		return "dev"
	}
	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			if len(s.Value) > 12 {
				return s.Value[:12]
			}
			return s.Value
		}
	}
	return "dev"
}

// Replica resolves a replica label for log records. It prefers POD_NAME, then
// HOSTNAME, then the OS hostname, returning "" when none is available.
func Replica() string {
	if v := os.Getenv("POD_NAME"); v != "" {
		return v
	}
	if v := os.Getenv("HOSTNAME"); v != "" {
		return v
	}
	if h, err := lookupHostname(); err == nil {
		return h
	}
	return ""
}

// RunServer starts srv and blocks until ctx is cancelled, then shuts it down
// gracefully within timeout. preShutdown, when non-nil, runs after the context
// is cancelled but before srv.Shutdown — use it for order-sensitive teardown
// such as stopping background workers. Its error is joined with the shutdown
// error.
//
// RunServer does not own signal handling: the caller passes a context already
// wired to signal.NotifyContext (or any cancellation source). The caller is
// also responsible for wrapping srv.Handler with otel.Handler and any service
// middleware before calling RunServer, so handlers are never double-wrapped.
//
// A clean shutdown (or a server that never started listening) returns nil;
// http.ErrServerClosed is treated as the normal stop signal.
func RunServer(ctx context.Context, srv *http.Server, timeout time.Duration, preShutdown func(context.Context) error) error {
	errCh := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errCh <- err
	}()

	select {
	case err := <-errCh:
		// Server stopped on its own (bind failure or early close).
		return err
	case <-ctx.Done():
	}

	// ctx is already done here -- it is what released the select. WithoutCancel
	// drops that cancellation while keeping the caller's values, so the
	// shutdown gets its own budget and still carries request-scoped state.
	shutCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()

	var preErr error
	if preShutdown != nil {
		preErr = preShutdown(shutCtx)
	}
	return errors.Join(preErr, srv.Shutdown(shutCtx))
}
