// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// jsonUnmarshal is encoding/json.Unmarshal, named so the fuzz target reads
// as the round-trip it checks.
var jsonUnmarshal = json.Unmarshal

// The client and the ingest handler round-trip through a real HTTP server.
func TestClient_PushAndPurge(t *testing.T) {
	reg := NewRegistry()
	mux := http.NewServeMux()
	(&IngestHandler{Registry: reg}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL).WithHTTPClient(srv.Client())
	ctx := context.Background()

	err := c.PushMap(ctx, "p-1", []IngestEntry{
		IngestEntryFor("cph_x", []byte("realsecret"), []string{"api.example.com"}),
	})
	if err != nil {
		t.Fatalf("PushMap: %v", err)
	}
	m, found := reg.Get("p-1")
	if !found {
		t.Fatal("p-1 not registered after push")
	}
	if v, ok := m.SubstituteValue("api.example.com", "cph_x"); !ok || v != "realsecret" {
		t.Fatalf("pushed map not usable: %q %v", v, ok)
	}

	if err := c.PurgeMap(ctx, "p-1"); err != nil {
		t.Fatalf("PurgeMap: %v", err)
	}
	if _, found := reg.Get("p-1"); found {
		t.Fatal("p-1 should be purged")
	}
}

func TestClient_NilIsNoop(t *testing.T) {
	var c *Client
	if err := c.PushMap(context.Background(), "p", nil); err != nil {
		t.Fatalf("nil push: %v", err)
	}
	if err := c.PurgeMap(context.Background(), "p"); err != nil {
		t.Fatalf("nil purge: %v", err)
	}
	if c.WithHTTPClient(http.DefaultClient) != nil || c.WithReplicas("h", "1") != nil || c.WithIngestToken("t") != nil {
		t.Fatal("option setters on a nil client must stay nil")
	}
	if NewClient("") != nil {
		t.Fatal("empty base URL should yield a nil client")
	}
	if NewClient("  https://egress.svc/  ") == nil {
		t.Fatal("non-empty base URL should yield a client")
	}
}

func TestClient_Non2xxIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := NewClient(srv.URL).WithHTTPClient(srv.Client())
	if err := c.PushMap(context.Background(), "p", nil); err == nil {
		t.Fatal("expected error on 500")
	}
}

func TestClient_DialFailureIsError(t *testing.T) {
	// Port 1 refuses; PushMap/PurgeMap surface the transport error.
	c := NewClient("http://127.0.0.1:1")
	if err := c.PushMap(context.Background(), "p", nil); err == nil {
		t.Fatal("expected a dial error from PushMap")
	}
	if err := c.PurgeMap(context.Background(), "p"); err == nil {
		t.Fatal("expected a dial error from PurgeMap")
	}
}

// A base URL with a control char makes http.NewRequest fail, surfacing an error
// from both client methods (the request-construction branch).
func TestClient_BadURLIsError(t *testing.T) {
	c := NewClient("http://\x7f-bad-host")
	if err := c.PushMap(context.Background(), "p", nil); err == nil {
		t.Fatal("PushMap with a bad URL should error")
	}
	if err := c.PurgeMap(context.Background(), "p"); err == nil {
		t.Fatal("PurgeMap with a bad URL should error")
	}
}

// TestNewClient_InstrumentedTransport pins the trace-propagation contract: the
// ingest client must carry the otel transport so pushes from a request-scoped
// ctx continue the caller's trace.
func TestNewClient_InstrumentedTransport(t *testing.T) {
	c := NewClient("http://egress.internal:9443")
	if c == nil {
		t.Fatal("NewClient returned nil for a non-empty base URL")
	}
	if _, ok := c.http.Transport.(*otelhttp.Transport); !ok {
		t.Fatalf("ingest client transport = %T, want *otelhttp.Transport", c.http.Transport)
	}
}

// WithReplicas installs the default resolver once and keeps an injected one.
func TestClient_WithReplicasResolver(t *testing.T) {
	c := NewClient("http://egress.internal:9443").WithReplicas(" replicas.internal ", " 9443 ")
	if c.replicasHost != "replicas.internal" || c.replicasPort != "9443" || c.resolve == nil {
		t.Fatalf("WithReplicas did not configure fan-out: %+v", c)
	}
	// The default resolver is the system one: an invalid name fails.
	if _, err := c.resolve(context.Background(), "nx.invalid."); err == nil {
		t.Fatal("default resolver should fail for an invalid name")
	}
	// An empty host is ignored.
	d := NewClient("http://egress.internal:9443").WithReplicas("", "9443")
	if d.replicasHost != "" || d.resolve != nil {
		t.Fatal("empty replicas host must not enable fan-out")
	}
}

// PushMapAllReplicas fans the push out to every resolved gateway replica so
// each holds the map.
func TestPushMapAllReplicas_FansOutToEveryReplica(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	// The test server's host:port; pretend the headless service resolves to it
	// twice (two "replicas" at the same test endpoint).
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	c := NewClient(srv.URL).WithHTTPClient(srv.Client())
	c.replicasHost = "egress-replicas"
	c.replicasPort = port
	// Resolve the headless service to the test endpoint twice (two "replicas").
	// PushMapAllReplicas reuses baseURL's scheme (http here), so each resolved IP
	// really receives a PUT and the handler counts both.
	c.resolve = func(context.Context, string) ([]string, error) { return []string{host, host}, nil }

	if err := c.PushMapAllReplicas(context.Background(), "p-1", []IngestEntry{{Placeholder: "cph_x"}}); err != nil {
		t.Fatalf("push: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["/internal/maps/p-1"] != 2 {
		t.Fatalf("fan-out should push to every replica, got %d hits", hits["/internal/maps/p-1"])
	}
}

// PurgeMapAllReplicas fans the DELETE out to every resolved gateway replica so
// a deleted principal's map is dropped on every replica, not just the one a
// load-balanced DELETE happens to reach.
func TestPurgeMapAllReplicas_FansOutToEveryReplica(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.Method == http.MethodDelete {
			hits[r.URL.Path]++
		}
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	c := NewClient(srv.URL).WithHTTPClient(srv.Client())
	c.replicasHost = "egress-replicas"
	c.replicasPort = port
	c.resolve = func(context.Context, string) ([]string, error) { return []string{host, host}, nil }

	if err := c.PurgeMapAllReplicas(context.Background(), "p-1"); err != nil {
		t.Fatalf("purge: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits["/internal/maps/p-1"] != 2 {
		t.Fatalf("purge fan-out should DELETE on every replica, got %d hits", hits["/internal/maps/p-1"])
	}
}

func TestPurgeMapAllReplicas_FallsBackWithoutReplicasHost(t *testing.T) {
	var del int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			del++
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewClient(srv.URL).WithHTTPClient(srv.Client())
	if err := c.PurgeMapAllReplicas(context.Background(), "p-1"); err != nil {
		t.Fatal(err)
	}
	if del != 1 {
		t.Fatalf("fallback should DELETE once to the service, got %d", del)
	}
}

func TestPurgeMapAllReplicas_NilClient(t *testing.T) {
	var c *Client
	if err := c.PurgeMapAllReplicas(context.Background(), "p"); err != nil {
		t.Fatal(err)
	}
}

func TestPushMapAllReplicas_FallsBackWithoutReplicasHost(t *testing.T) {
	var hit int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewClient(srv.URL).WithHTTPClient(srv.Client())
	// No replicas host → falls back to the single load-balanced PushMap.
	if err := c.PushMapAllReplicas(context.Background(), "p-1", nil); err != nil {
		t.Fatal(err)
	}
	if hit != 1 {
		t.Fatalf("fallback should push once to the service, got %d", hit)
	}
}

func TestPushMapAllReplicas_NilClient(t *testing.T) {
	var c *Client
	if err := c.PushMapAllReplicas(context.Background(), "p", nil); err != nil {
		t.Fatal(err)
	}
}

// When resolution fails, both fan-outs fall back to the load-balanced service.
func TestAllReplicas_ResolveFailureFallsBack(t *testing.T) {
	var puts, dels int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPut:
			puts++
		case http.MethodDelete:
			dels++
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewClient(srv.URL).WithHTTPClient(srv.Client()).WithReplicas("egress-replicas", "1")
	c.resolve = func(context.Context, string) ([]string, error) { return nil, net.ErrClosed }
	if err := c.PushMapAllReplicas(context.Background(), "p-1", nil); err != nil {
		t.Fatal(err)
	}
	if err := c.PurgeMapAllReplicas(context.Background(), "p-1"); err != nil {
		t.Fatal(err)
	}
	if puts != 1 || dels != 1 {
		t.Fatalf("fallback should hit the service once each: puts=%d dels=%d", puts, dels)
	}
}

// Every replica failing surfaces an error; one success out of several does not.
func TestAllReplicas_ErrorOnlyWhenEveryPushFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())

	c := NewClient(srv.URL).WithHTTPClient(srv.Client()).WithReplicas("egress-replicas", port)
	// One live replica and one that refuses: no error.
	c.resolve = func(context.Context, string) ([]string, error) { return []string{host, "127.0.0.1"}, nil }
	c.replicasPort = port
	if err := c.PushMapAllReplicas(context.Background(), "p-1", nil); err != nil {
		t.Fatalf("one healthy replica should suffice: %v", err)
	}
	// Every replica refuses (port 1): error.
	c.replicasPort = "1"
	if err := c.PushMapAllReplicas(context.Background(), "p-1", nil); err == nil {
		t.Fatal("all replicas failing should error")
	}
	if err := c.PurgeMapAllReplicas(context.Background(), "p-1"); err == nil {
		t.Fatal("all replicas failing should error")
	}
	// A replica IP that cannot form a URL is a construction error, not a dial.
	c.resolve = func(context.Context, string) ([]string, error) { return []string{"\x7f"}, nil }
	if err := c.PushMapAllReplicas(context.Background(), "p-1", nil); err == nil {
		t.Fatal("unbuildable replica URL should error")
	}
	if err := c.PurgeMapAllReplicas(context.Background(), "p-1"); err == nil {
		t.Fatal("unbuildable replica URL should error")
	}
}
