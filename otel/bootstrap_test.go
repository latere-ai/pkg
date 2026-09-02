// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"context"
	"errors"
	"net"
	"net/http"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func TestBootstrap_NoEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	logger, shutdown, err := Bootstrap(context.Background(), Config{ServiceName: "svc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Fatal("nil logger")
	}
	logger.Info("hello")
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
}

func TestBootstrap_WithEndpoint(t *testing.T) {
	srv := otlpServer(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	logger, shutdown, err := Bootstrap(context.Background(), Config{
		ServiceName: "svc",
		Version:     "1.2.3",
		Replica:     "pod-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	logger.Info("hello")
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
}

func TestBootstrap_DerivesVersionAndReplica(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("POD_NAME", "derived-pod")
	// Empty Version/Replica must trigger the build-info / env fallbacks
	// without error.
	logger, shutdown, err := Bootstrap(context.Background(), Config{ServiceName: "svc"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	logger.Info("hello")
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
}

func TestBootstrap_LogExporterErrorBubbles(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4318")
	orig := newLogExporter
	t.Cleanup(func() { newLogExporter = orig })
	newLogExporter = func(ctx context.Context, endpoint string) (sdklog.Exporter, error) {
		return nil, errors.New("injected")
	}
	logger, shutdown, err := Bootstrap(context.Background(), Config{ServiceName: "svc"})
	if err == nil {
		t.Fatal("expected error from log exporter path")
	}
	// Logger must remain usable despite the OTLP log path failing.
	if logger == nil {
		t.Fatal("nil logger on error path")
	}
	logger.Info("still works")
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown error: %v", err)
	}
}

func TestVersion_Override(t *testing.T) {
	if got := Version("v9.9.9"); got != "v9.9.9" {
		t.Fatalf("got %q, want v9.9.9", got)
	}
}

func TestVersion_NoBuildInfo(t *testing.T) {
	orig := readBuildInfo
	t.Cleanup(func() { readBuildInfo = orig })
	readBuildInfo = func() (*debug.BuildInfo, bool) { return nil, false }
	if got := Version(""); got != "dev" {
		t.Fatalf("got %q, want dev", got)
	}
}

func TestVersion_MainVersion(t *testing.T) {
	orig := readBuildInfo
	t.Cleanup(func() { readBuildInfo = orig })
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Main: debug.Module{Version: "v1.4.0"}}, true
	}
	if got := Version(""); got != "v1.4.0" {
		t.Fatalf("got %q, want v1.4.0", got)
	}
}

func TestVersion_DevelFallsToRevision(t *testing.T) {
	orig := readBuildInfo
	t.Cleanup(func() { readBuildInfo = orig })
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Main:     debug.Module{Version: "(devel)"},
			Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abcdef0123456789"}},
		}, true
	}
	if got := Version(""); got != "abcdef012345" {
		t.Fatalf("got %q, want abcdef012345 (12 chars)", got)
	}
}

func TestVersion_ShortRevision(t *testing.T) {
	orig := readBuildInfo
	t.Cleanup(func() { readBuildInfo = orig })
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}},
		}, true
	}
	if got := Version(""); got != "abc123" {
		t.Fatalf("got %q, want abc123", got)
	}
}

func TestVersion_NoVersionNoRevision(t *testing.T) {
	orig := readBuildInfo
	t.Cleanup(func() { readBuildInfo = orig })
	readBuildInfo = func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "GOOS", Value: "linux"}}}, true
	}
	if got := Version(""); got != "dev" {
		t.Fatalf("got %q, want dev", got)
	}
}

func TestReplica_PodName(t *testing.T) {
	t.Setenv("POD_NAME", "pod-x")
	t.Setenv("HOSTNAME", "host-y")
	if got := Replica(); got != "pod-x" {
		t.Fatalf("got %q, want pod-x", got)
	}
}

func TestReplica_Hostname(t *testing.T) {
	t.Setenv("POD_NAME", "")
	t.Setenv("HOSTNAME", "host-y")
	if got := Replica(); got != "host-y" {
		t.Fatalf("got %q, want host-y", got)
	}
}

func TestReplica_OSHostname(t *testing.T) {
	t.Setenv("POD_NAME", "")
	t.Setenv("HOSTNAME", "")
	orig := lookupHostname
	t.Cleanup(func() { lookupHostname = orig })
	lookupHostname = func() (string, error) { return "os-host", nil }
	if got := Replica(); got != "os-host" {
		t.Fatalf("got %q, want os-host", got)
	}
}

func TestReplica_HostnameError(t *testing.T) {
	t.Setenv("POD_NAME", "")
	t.Setenv("HOSTNAME", "")
	orig := lookupHostname
	t.Cleanup(func() { lookupHostname = orig })
	lookupHostname = func() (string, error) { return "", errors.New("injected") }
	if got := Replica(); got != "" {
		t.Fatalf("got %q, want empty", got)
	}
}

func TestRunServer_GracefulShutdown(t *testing.T) {
	srv := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunServer(ctx, srv, time.Second, nil) }()

	// Give ListenAndServe a moment to start, then trigger graceful shutdown.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("graceful shutdown returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunServer did not return after cancel")
	}
}

func TestRunServer_PreShutdownError(t *testing.T) {
	srv := &http.Server{
		Addr:    "127.0.0.1:0",
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}),
	}
	ctx, cancel := context.WithCancel(context.Background())
	want := errors.New("pre-shutdown failed")
	done := make(chan error, 1)
	go func() {
		done <- RunServer(ctx, srv, time.Second, func(context.Context) error { return want })
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("got %v, want pre-shutdown error joined", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RunServer did not return after cancel")
	}
}

func FuzzVersion(f *testing.F) {
	f.Add("v1.0.0")
	f.Add("")
	f.Add("(devel)")
	f.Add("abcdef0123456789")
	f.Fuzz(func(t *testing.T, override string) {
		// Must never panic and must return non-empty for any input: a
		// non-empty override is echoed, an empty one falls back to build info
		// or "dev".
		if got := Version(override); got == "" {
			t.Errorf("Version(%q) returned empty", override)
		}
	})
}

func TestRunServer_ListenError(t *testing.T) {
	// Occupy a port so the server's ListenAndServe fails to bind.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := &http.Server{Addr: ln.Addr().String()}
	err = RunServer(context.Background(), srv, time.Second, nil)
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("got %v, want bind error", err)
	}
}
