package otel

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransport_NilBaseUsesDefault(t *testing.T) {
	rt := Transport(nil)
	if rt == nil {
		t.Fatal("nil transport")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	client := &http.Client{Transport: rt}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

type recordingRT struct {
	called bool
}

func (r *recordingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	r.called = true
	return http.DefaultTransport.RoundTrip(req)
}

func TestTransport_WrapsCustomBase(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)

	base := &recordingRT{}
	client := &http.Client{Transport: Transport(base)}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if !base.called {
		t.Fatal("custom base transport was not invoked")
	}
}

func TestHTTPClient(t *testing.T) {
	c := HTTPClient()
	if c == nil || c.Transport == nil {
		t.Fatal("HTTPClient returned client without instrumented transport")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
}
