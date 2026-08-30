package otel

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel/codes"
)

// TestHandlerMarksServerErrorSpans pins the property a backend error panel
// depends on: a 5xx response must leave the server span with Error status. An
// Unset span is indistinguishable from a healthy one when querying by status.
func TestHandlerMarksServerErrorSpans(t *testing.T) {
	sr := installRecorder(t)

	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}), "svc")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/fail", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := spans[0].Status().Code; got != codes.Error {
		t.Errorf("span status = %v, want %v", got, codes.Error)
	}
}

// TestHandlerLeavesSuccessSpansUnset guards the other direction: marking every
// span Error would be just as useless as marking none.
func TestHandlerLeavesSuccessSpansUnset(t *testing.T) {
	sr := installRecorder(t)

	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}), "svc")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/ok", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := spans[0].Status().Code; got == codes.Error {
		t.Errorf("span status = %v, want not %v", got, codes.Error)
	}
}

// TestHandlerDoesNotMarkClientErrors keeps 4xx off the error panel. A 404 is
// the caller's problem, and treating it as a server error buries real faults.
func TestHandlerDoesNotMarkClientErrors(t *testing.T) {
	sr := installRecorder(t)

	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}), "svc")

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/missing", nil))

	spans := sr.Ended()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	if got := spans[0].Status().Code; got == codes.Error {
		t.Errorf("span status = %v for 404, want not %v", got, codes.Error)
	}
}
