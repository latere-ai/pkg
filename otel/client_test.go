// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package otel

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// A client span's url.full keeps the scheme, host and path of the request and
// none of its query, fragment or user info, whatever the request carried.
func TestTransportKeepsNoQueryOnTheSpan(t *testing.T) {
	rec := installRecorder(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "x" {
			t.Errorf("the server lost the query: %q", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/files/alice/notes?token=x&cursor=c2#part", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.URL.User = url.UserPassword("user", "pass")
	resp, err := (&http.Client{Transport: Transport(nil)}).Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()

	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("%d spans, want the one client span", len(spans))
	}
	var full string
	for _, kv := range spans[0].Attributes() {
		v := kv.Value.String()
		if strings.Contains(v, "token") || strings.Contains(v, "cursor") || strings.Contains(v, "part") || strings.Contains(v, "pass") {
			t.Errorf("%s carries the query, fragment or user info: %q", kv.Key, v)
		}
		if kv.Key == "url.full" {
			full = v
		}
	}
	if want := srv.URL + "/files/alice/notes"; full != want {
		t.Fatalf("url.full %q, want %q", full, want)
	}
}
