// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func ingestServer(t *testing.T) (*Registry, *httptest.Server) {
	t.Helper()
	reg := NewRegistry()
	mux := http.NewServeMux()
	(&IngestHandler{Registry: reg}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return reg, srv
}

func TestIngest_PutAndDelete(t *testing.T) {
	reg, srv := ingestServer(t)
	body := `{"entries":[{"placeholder":"cph_x","secret":"` +
		base64.StdEncoding.EncodeToString([]byte("realsecret")) +
		`","allowed_hosts":["api.example.com"]}]}`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/internal/maps/p-1", strings.NewReader(body))
	resp, err := srv.Client().Do(req)
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put: %v code=%d", err, resp.StatusCode)
	}
	defer resp.Body.Close()
	m, found := reg.Get("p-1")
	if !found {
		t.Fatal("p-1 not registered")
	}
	if v, ok := m.SubstituteValue("api.example.com", "cph_x"); !ok || v != "realsecret" {
		t.Fatalf("pushed map not usable: %q %v", v, ok)
	}

	// DELETE purges.
	dreq, _ := http.NewRequest(http.MethodDelete, srv.URL+"/internal/maps/p-1", nil)
	dresp, err := srv.Client().Do(dreq)
	if err != nil || dresp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %v code=%d", err, dresp.StatusCode)
	}
	defer dresp.Body.Close()
	if _, found := reg.Get("p-1"); found {
		t.Fatal("p-1 should be purged")
	}
}

func TestIngest_BadRequests(t *testing.T) {
	_, srv := ingestServer(t)
	cases := []string{
		`not json`,
		`{"entries":[{"placeholder":"cph_x","secret":"!!not base64!!","allowed_hosts":["h"]}]}`,
	}
	for i, body := range cases {
		req, _ := http.NewRequest(http.MethodPut, srv.URL+"/internal/maps/p-1", strings.NewReader(body))
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		code := resp.StatusCode
		resp.Body.Close()
		if code != http.StatusBadRequest {
			t.Fatalf("case %d: expected 400, got %d", i, code)
		}
	}
}

func TestIngest_MissingID(t *testing.T) {
	reg := NewRegistry()
	h := &IngestHandler{Registry: reg}
	req := httptest.NewRequest(http.MethodPut, "/internal/maps/", strings.NewReader(`{"entries":[]}`))
	req.SetPathValue("id", "")
	rr := httptest.NewRecorder()
	h.put(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("empty id should be 400, got %d", rr.Code)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read boom") }

// A request body that errors on read yields 400 from the ingest handler.
func TestIngest_ReadBodyError(t *testing.T) {
	h := &IngestHandler{Registry: NewRegistry()}
	req := httptest.NewRequest(http.MethodPut, "/internal/maps/p", errReader{})
	req.SetPathValue("id", "p")
	rr := httptest.NewRecorder()
	h.put(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("read error should yield 400, got %d", rr.Code)
	}
}

func TestIngest_TokenRequiredWhenConfigured(t *testing.T) {
	reg := NewRegistry()
	mux := http.NewServeMux()
	(&IngestHandler{Registry: reg, Token: "s3cr3t"}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	body := `{"entries":[]}`
	// No Authorization: rejected, and the map is not touched.
	noauth, _ := http.NewRequest(http.MethodPut, srv.URL+"/internal/maps/p-1", strings.NewReader(body))
	noauthResp, err := srv.Client().Do(noauth)
	if noauthResp != nil {
		defer noauthResp.Body.Close()
	}
	if err != nil || noauthResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing token: want 401, got %v code=%d", err, noauthResp.StatusCode)
	}
	// Wrong token: rejected.
	wrong, _ := http.NewRequest(http.MethodDelete, srv.URL+"/internal/maps/p-1", nil)
	wrong.Header.Set("Authorization", "Bearer nope")
	wrongResp, err := srv.Client().Do(wrong)
	if wrongResp != nil {
		defer wrongResp.Body.Close()
	}
	if err != nil || wrongResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong token: want 401, got %v code=%d", err, wrongResp.StatusCode)
	}
	// Correct token: accepted.
	ok, _ := http.NewRequest(http.MethodPut, srv.URL+"/internal/maps/p-1", strings.NewReader(body))
	ok.Header.Set("Authorization", "Bearer s3cr3t")
	okResp, err := srv.Client().Do(ok)
	if okResp != nil {
		defer okResp.Body.Close()
	}
	if err != nil || okResp.StatusCode != http.StatusNoContent {
		t.Fatalf("correct token: want 204, got %v code=%d", err, okResp.StatusCode)
	}
}

// The Client attaches the ingest token so a token-guarded handler accepts its
// pushes and purges.
func TestClient_SendsIngestToken(t *testing.T) {
	reg := NewRegistry()
	mux := http.NewServeMux()
	(&IngestHandler{Registry: reg, Token: "tok"}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c := NewClient(srv.URL).WithHTTPClient(srv.Client()).WithIngestToken("tok")
	if err := c.PushMap(context.Background(), "p-1", []IngestEntry{{Placeholder: "cph_x"}}); err != nil {
		t.Fatalf("push with token: %v", err)
	}
	if err := c.PurgeMap(context.Background(), "p-1"); err != nil {
		t.Fatalf("purge with token: %v", err)
	}
	// Without the token the same handler rejects the push.
	if err := NewClient(srv.URL).WithHTTPClient(srv.Client()).PushMap(context.Background(), "p-2", nil); err == nil {
		t.Fatal("push without token should fail against a guarded handler")
	}
}

// The Authorization scheme is case-insensitive (RFC 7235), so a client that
// sends "bearer" is accepted.
func TestIngest_LowercaseSchemeAccepted(t *testing.T) {
	reg := NewRegistry()
	mux := http.NewServeMux()
	(&IngestHandler{Registry: reg, Token: "s3cr3t"}).Mount(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/internal/maps/p-1", strings.NewReader(`{"entries":[]}`))
	req.Header.Set("Authorization", "bearer s3cr3t")
	resp, err := srv.Client().Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatalf("lowercase scheme: want 204, got %v code=%d", err, resp.StatusCode)
	}
}

// DecodeIngestBody round-trips what IngestEntryFor encodes, and rejects a
// body whose secret is not base64.
func TestDecodeIngestBody(t *testing.T) {
	body := `{"entries":[{"placeholder":"cph_x","secret":"` + base64.StdEncoding.EncodeToString([]byte{0, 1, 255}) + `","allowed_hosts":["h"]}]}`
	entries, err := DecodeIngestBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || string(entries[0].Secret) != "\x00\x01\xff" || string(entries[0].Placeholder) != "cph_x" {
		t.Fatalf("decoded %+v", entries)
	}
	if _, err := DecodeIngestBody([]byte(`{"entries":[{"secret":"%%%"}]}`)); err == nil || err.Error() != "invalid base64 secret" {
		t.Fatalf("bad base64: err=%v", err)
	}
	if _, err := DecodeIngestBody([]byte(`{`)); err == nil || !strings.HasPrefix(err.Error(), "invalid json:") {
		t.Fatalf("bad json: err=%v", err)
	}
}

// DecodeIngestBody never panics, and every entry it returns carries a secret
// that re-encodes to what the body held.
func FuzzDecodeIngestBody(f *testing.F) {
	f.Add([]byte(`{"entries":[{"placeholder":"cph_x","secret":"c2VjcmV0","allowed_hosts":["h"]}]}`))
	f.Add([]byte(`not json`))
	f.Add([]byte(`{"entries":[{"secret":"!!"}]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		entries, err := DecodeIngestBody(body)
		if err != nil {
			if entries != nil {
				t.Fatal("entries returned alongside an error")
			}
			return
		}
		var in IngestBody
		if jerr := jsonUnmarshal(body, &in); jerr != nil {
			t.Fatalf("decoded a body json rejects: %v", jerr)
		}
		if len(entries) != len(in.Entries) {
			t.Fatalf("decoded %d entries from %d", len(entries), len(in.Entries))
		}
		for i, e := range entries {
			if base64.StdEncoding.EncodeToString(e.Secret) != in.Entries[i].Secret {
				t.Fatalf("entry %d secret does not round-trip", i)
			}
		}
	})
}
