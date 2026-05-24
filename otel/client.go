package otel

import (
	"net/http"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

// Transport wraps base with OpenTelemetry instrumentation: it creates a client
// span per outbound request and injects the W3C trace context headers so the
// receiving service (instrumented with Handler) continues the same trace. Pass
// nil to wrap http.DefaultTransport.
//
// Use this for every service-to-service call. Without it, server spans exist on
// both sides but are not linked, so traces stay islanded per service.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return otelhttp.NewTransport(base)
}

// HTTPClient returns an *http.Client whose Transport is instrumented via
// Transport. It is a convenience for callers that do not otherwise customise
// the client.
func HTTPClient() *http.Client {
	return &http.Client{Transport: Transport(nil)}
}
