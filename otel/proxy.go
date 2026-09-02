package otel

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/time/rate"
)

// scopeName is the instrumentation scope for telemetry this package emits
// about itself.
const scopeName = "latere.ai/x/pkg/otel"

// maxTelemetryBody caps a single forwarded browser payload. OTLP/HTTP batches
// from @opentelemetry/web are small; the cap bounds abuse of the public route.
const maxTelemetryBody = 1 << 20 // 1 MiB

// telemetryClient forwards browser payloads to the collector. A package var so
// tests can adjust the timeout/transport without a live backend.
var telemetryClient = &http.Client{Timeout: 10 * time.Second, Transport: Transport(nil)}

// telemetryRateEnv names the sustained byte budget, in bytes per second, that
// the relay will forward. Zero or negative disables the limit.
const telemetryRateEnv = "LATERE_TELEMETRY_PROXY_BYTES_PER_SEC"

// defaultTelemetryRate is the budget when telemetryRateEnv is unset: 64 KiB/s,
// roughly two orders of magnitude above what a browser fleet of this size
// produces, and a ceiling rather than a target.
//
// The route is anonymous by construction. A SPA exports spans before the user
// has logged in, so there is no credential to demand, and a bearer token
// shipped to the browser to satisfy one would be public the moment it loaded.
// What is left is a budget: the backend bills by volume ingested, so the relay
// bounds the volume it will pass on.
const defaultTelemetryRate = 64 << 10

// newTelemetryLimiter builds the relay's byte budget from the environment, or
// nil when the limit is disabled.
//
// The burst never falls below maxTelemetryBody. rate.Limiter rejects any
// reservation larger than its burst outright, so a smaller burst would make a
// legal maximum-size payload permanently unforwardable rather than merely
// delayed.
func newTelemetryLimiter() *rate.Limiter {
	bps := defaultTelemetryRate
	if raw := os.Getenv(telemetryRateEnv); raw != "" {
		n, err := strconv.Atoi(strings.TrimSpace(raw))
		switch {
		case err != nil:
			// An unparseable budget keeps the default. Falling back to
			// unlimited would turn a typo into an uncapped bill.
		case n <= 0:
			return nil
		default:
			bps = n
		}
	}
	return rate.NewLimiter(rate.Limit(bps), max(bps, maxTelemetryBody))
}

// telemetryRejectCounter resolves the counter of payloads the budget refused.
//
// A budget that drops silently is worse than none: browser traces stop
// arriving and the cause is invisible, which is the failure this package
// exists to prevent. The counter is what says the budget is biting and needs
// raising, as opposed to the SPA having stopped exporting.
//
// Resolved per handler rather than once per process so a test can install a
// reader first. The global provider delegates instruments created before
// Bootstrap installs it, so mounting order does not change the outcome.
func telemetryRejectCounter() metric.Int64Counter {
	c, err := otel.Meter(scopeName).Int64Counter(
		"latere.telemetry_proxy.rejected",
		metric.WithDescription("Browser telemetry payloads dropped by the relay byte budget."),
		metric.WithUnit("{payload}"),
	)
	if err != nil {
		// The API returns a usable noop alongside the error. A counter that
		// cannot be built must not take the relay down with it.
		slog.Warn("telemetry proxy reject counter unavailable", "err", err)
	}
	return c
}

// exporterHeaders parses OTEL_EXPORTER_OTLP_HEADERS the way the specification
// defines it: comma-separated key=value pairs, each side percent-encoded, with
// surrounding whitespace ignored.
//
// The SDK's own exporters read this variable themselves. The relay does not go
// through an SDK exporter, so it has to read it too, or browser telemetry is
// the one signal that arrives unauthenticated.
//
// A pair that does not parse is skipped rather than failing the handler. A
// malformed entry should cost that one header, not every browser span.
func exporterHeaders() map[string]string {
	return parseExporterHeaders(os.Getenv("OTEL_EXPORTER_OTLP_HEADERS"))
}

// parseExporterHeaders is the parsing half, split out so it can be exercised
// without the environment. An env var cannot hold every byte a fuzzer will
// try, so a target that goes through os.Setenv tests the harness rather than
// the parser.
func parseExporterHeaders(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	out := map[string]string{}
	for pair := range strings.SplitSeq(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		key, err := url.QueryUnescape(strings.TrimSpace(k))
		if err != nil || !validHeaderName(key) {
			continue
		}
		val, err := url.QueryUnescape(strings.TrimSpace(v))
		if err != nil || strings.ContainsAny(val, "\r\n\x00") {
			continue
		}
		out[key] = val
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// validHeaderName reports whether s is a legal HTTP field name, the RFC 7230
// token production.
//
// Percent-decoding is what makes this necessary rather than paranoid: the
// value is decoded before it becomes a header name, so "%09" arrives as a tab
// and "%0d%0a" as a line break. Either would produce a malformed request, and
// a decoded CRLF in a name is header injection into the request the relay
// sends onward.
func validHeaderName(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}

// TelemetryProxy returns an http.Handler that forwards browser-originated
// OTLP/HTTP payloads to the in-cluster collector named by
// OTEL_EXPORTER_OTLP_ENDPOINT. Browsers cannot reach the internal collector, so
// a service mounts this on a same-origin route (e.g. "/v1/telemetry/") and the
// SPA's @opentelemetry/web exporter posts to it. Being same-origin, it needs no
// CORS and rides the service's existing TLS and ingress controls.
//
// The subpath after prefix is appended to the collector base, so a POST to
// "{prefix}/v1/traces" is forwarded to "{collector}/v1/traces". Only POST is
// accepted, bodies are capped at 1 MiB, and the forwarded volume is bounded by
// the byte budget described on defaultTelemetryRate. When the endpoint is unset
// the handler returns 503 so the SPA degrades quietly.
func TelemetryProxy(prefix string) http.Handler {
	endpoint := strings.TrimRight(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"), "/")
	limiter := newTelemetryLimiter()
	rejects := telemetryRejectCounter()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if endpoint == "" {
			http.Error(w, "telemetry disabled", http.StatusServiceUnavailable)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		sub := strings.TrimPrefix(r.URL.Path, prefix)
		if !strings.HasPrefix(sub, "/") {
			sub = "/" + sub
		}

		body, err := io.ReadAll(io.LimitReader(r.Body, maxTelemetryBody+1))
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		if len(body) > maxTelemetryBody {
			http.Error(w, "telemetry payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		// The budget is charged in bytes, not requests, because the backend
		// bills by volume: a request-per-second cap leaves 1 MiB payloads free
		// to multiply the bill by six orders of magnitude within it.
		if !allowTelemetryBytes(r.Context(), w, limiter, rejects, len(body)) {
			return
		}

		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, endpoint+sub, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "build request", http.StatusInternalServerError)
			return
		}
		// Preserve the OTLP content negotiation headers the SDK set.
		if ct := r.Header.Get("Content-Type"); ct != "" {
			req.Header.Set("Content-Type", ct)
		}
		if ce := r.Header.Get("Content-Encoding"); ce != "" {
			req.Header.Set("Content-Encoding", ce)
		}
		// Then the collector's own credentials. A backend reached over the
		// public internet authenticates by header, and the browser has no way
		// to hold that secret: the whole point of relaying through the service
		// is that the credential stays server side. Without this the relay
		// works against an in-cluster collector and 401s against a vendor,
		// which is a failure that only appears at the cutover.
		for k, v := range exporterHeaders() {
			req.Header.Set(k, v)
		}

		resp, err := telemetryClient.Do(req)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, maxTelemetryBody))
	})
}

// allowTelemetryBytes charges n bytes against the relay's budget, writing a 429
// and reporting false when the budget is spent.
//
// Retry-After carries the limiter's own answer for when the budget next covers
// this payload. The OTLP specification has exporters honor that header, so
// omitting it converts a rate limit into a retry storm against the same route.
func allowTelemetryBytes(ctx context.Context, w http.ResponseWriter, limiter *rate.Limiter, rejects metric.Int64Counter, n int) bool {
	if limiter == nil {
		return true
	}
	now := time.Now()
	rsv := limiter.ReserveN(now, n)
	// !OK means n exceeds the burst ceiling and no wait would ever admit it.
	// maxTelemetryBody bounds n and the burst is at least that, so this is
	// unreachable through the handler; it is here so a future cap change
	// fails closed instead of panicking on an infinite delay.
	if !rsv.OK() {
		rejects.Add(ctx, 1)
		w.Header().Set("Retry-After", "1")
		http.Error(w, "telemetry rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	if d := rsv.DelayFrom(now); d > 0 {
		// Cancel returns the tokens: the payload is being dropped, not
		// queued, so holding them would penalise the next caller twice.
		rsv.CancelAt(now)
		rejects.Add(ctx, 1)
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(d.Seconds()))))
		http.Error(w, "telemetry rate limit exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}
