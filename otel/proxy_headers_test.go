package otel

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// recordUpstream returns a server that captures the headers it is sent.
func recordUpstream(t *testing.T) (*httptest.Server, func() http.Header) {
	t.Helper()
	var (
		mu  sync.Mutex
		got http.Header
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = r.Header.Clone()
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, func() http.Header {
		mu.Lock()
		defer mu.Unlock()
		return got
	}
}

// TestTelemetryProxy_ForwardsCollectorCredentials is the browser half of the
// vendor migration. The relay does not go through an SDK exporter, so it has
// to read OTEL_EXPORTER_OTLP_HEADERS itself; otherwise browser spans are the
// one signal that reaches an authenticated backend unauthenticated.
func TestTelemetryProxy_ForwardsCollectorCredentials(t *testing.T) {
	upstream, headers := recordUpstream(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer%20vendor-token,X-Dataset=prod")

	h := TelemetryProxy("/v1/telemetry")
	req := httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	got := headers()
	if v := got.Get("Authorization"); v != "Bearer vendor-token" {
		t.Errorf("Authorization = %q, want %q", v, "Bearer vendor-token")
	}
	if v := got.Get("X-Dataset"); v != "prod" {
		t.Errorf("X-Dataset = %q, want %q", v, "prod")
	}
	// The negotiation headers must survive alongside the credentials.
	if v := got.Get("Content-Type"); v != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", v)
	}
}

// TestTelemetryProxy_BrowserCannotOverrideCredentials matters because this
// route is reachable by anything that can reach the service. A caller must not
// be able to supply its own Authorization and have the relay pass it upstream.
func TestTelemetryProxy_BrowserCannotOverrideCredentials(t *testing.T) {
	upstream, headers := recordUpstream(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer%20real-token")

	h := TelemetryProxy("/v1/telemetry")
	req := httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer attacker-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if v := headers().Get("Authorization"); v != "Bearer real-token" {
		t.Errorf("Authorization = %q; the caller's header reached the collector", v)
	}
}

// TestTelemetryProxy_NoCredentialsConfigured keeps the in-cluster case working,
// where the collector needs no header at all.
func TestTelemetryProxy_NoCredentialsConfigured(t *testing.T) {
	upstream, headers := recordUpstream(t)
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", upstream.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "")

	h := TelemetryProxy("/v1/telemetry")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/telemetry/v1/traces", strings.NewReader("{}")))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if v := headers().Get("Authorization"); v != "" {
		t.Errorf("Authorization = %q, want none", v)
	}
}

func TestExporterHeaders(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{"empty", "", nil},
		{"single", "k=v", map[string]string{"k": "v"}},
		{"multiple", "a=1,b=2", map[string]string{"a": "1", "b": "2"}},
		{"percent decoded", "Authorization=Bearer%20t", map[string]string{"Authorization": "Bearer t"}},
		{"surrounding space ignored", " a = 1 , b = 2 ", map[string]string{"a": "1", "b": "2"}},
		{"value may contain equals", "k=a=b", map[string]string{"k": "a=b"}},
		{"empty value kept", "k=", map[string]string{"k": ""}},
		// A malformed entry costs that header, not the whole batch.
		{"pair without equals skipped", "novalue,k=v", map[string]string{"k": "v"}},
		{"empty key skipped", "=v,k=v", map[string]string{"k": "v"}},
		{"all malformed yields nil", "novalue", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", tc.raw)
			got := exporterHeaders()
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for k, want := range tc.want {
				if got[k] != want {
					t.Errorf("[%q] = %q, want %q", k, got[k], want)
				}
			}
		})
	}
}

func FuzzParseExporterHeaders(f *testing.F) {
	for _, s := range []string{"", "k=v", "a=1,b=2", "Authorization=Bearer%20t", "=", ",,,", "%zz=v", "k=%"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		// Every key must be usable as a header name. A key carrying a colon,
		// CR or LF would let a malformed variable inject a second header into
		// the request the relay sends to the collector.
		for k, v := range parseExporterHeaders(raw) {
			if k == "" || strings.ContainsAny(k, " \t\r\n:") {
				t.Errorf("unusable header name %q from %q", k, raw)
			}
			if strings.ContainsAny(v, "\r\n") {
				t.Errorf("header value %q from %q carries a line break", v, raw)
			}
		}
	})
}
