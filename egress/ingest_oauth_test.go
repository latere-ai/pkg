// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

const oauthBody = `{"entries":[{"placeholder":"cph_o","allowed_hosts":["h"],"kind":"oauth_client_credentials","substitute_body":true,
	"oauth":{"token_url":"https://as.example/token","client_id":"id","client_secret":"s","scope":"a b","audience":"aud"}}]}`

func TestDecodeIngestBody_OAuthEntry(t *testing.T) {
	entries, err := DecodeIngestBody([]byte(oauthBody))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	e := entries[0]
	if string(e.Placeholder) != "cph_o" || len(e.Secret) != 0 || !e.SubstituteBody || e.Resolve == nil || len(e.AllowedHosts) != 1 {
		t.Fatalf("decoded %+v", e)
	}
}

// Each decode owns its resolver: one map's entry caches its token, and a
// second decode of the same body mints again rather than sharing the cache.
func TestDecodeIngestBody_OAuthCachePerMap(t *testing.T) {
	ts := newTokenServer(t)
	body := strings.Replace(oauthBody, "https://as.example/token", ts.srv.URL, 1)
	first, err := DecodeIngestBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	second, _ := DecodeIngestBody([]byte(body))
	for range 2 {
		if b, err := first[0].Resolve(context.Background()); err != nil || string(b) != "tok-1" {
			t.Fatalf("first: %q %v", b, err)
		}
	}
	if ts.mints.Load() != 1 {
		t.Fatalf("mints = %d, want 1 (cached within the map)", ts.mints.Load())
	}
	if _, err := second[0].Resolve(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ts.mints.Load() != 2 {
		t.Fatalf("mints = %d, want 2 (a second map has its own cache)", ts.mints.Load())
	}
}

func TestDecodeIngestBody_OAuthFieldsReachResolver(t *testing.T) {
	var in IngestBody
	if err := json.Unmarshal([]byte(oauthBody), &in); err != nil {
		t.Fatal(err)
	}
	cc, err := in.Entries[0].OAuth.resolver()
	if err != nil {
		t.Fatal(err)
	}
	want := OAuthClientCredentials{TokenURL: "https://as.example/token", ClientID: "id", ClientSecret: "s", Scope: "a b", Audience: "aud"}
	if cc.TokenURL != want.TokenURL || cc.ClientID != want.ClientID || cc.ClientSecret != want.ClientSecret || cc.Scope != want.Scope || cc.Audience != want.Audience {
		t.Fatalf("resolver = %+v", cc)
	}
}

func TestDecodeIngestBody_StaticKindsAndSubstituteBody(t *testing.T) {
	body := `{"entries":[
		{"placeholder":"cph_a","secret":"c2VjcmV0","allowed_hosts":["h"]},
		{"placeholder":"cph_b","secret":"c2VjcmV0","allowed_hosts":["h"],"kind":"static","substitute_body":true}]}`
	entries, err := DecodeIngestBody([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range entries {
		if string(e.Secret) != "secret" || e.Resolve != nil {
			t.Fatalf("entry %d = %+v", i, e)
		}
	}
	if entries[0].SubstituteBody || !entries[1].SubstituteBody {
		t.Fatal("substitute_body not carried")
	}
}

func TestDecodeIngestBody_RejectsBadKindAndMissingOAuthFields(t *testing.T) {
	cases := map[string]string{
		`{"entries":[{"placeholder":"cph_x","kind":"magic"}]}`:                                                                              `entry 0 (cph_x): unknown kind "magic"`,
		`{"entries":[{"placeholder":"cph_x","kind":"oauth_client_credentials"}]}`:                                                           `entry 0 (cph_x): missing oauth`,
		`{"entries":[{"placeholder":"cph_x","kind":"oauth_client_credentials","oauth":{"client_id":"i","client_secret":"s"}}]}`:             `entry 0 (cph_x): missing oauth.token_url`,
		`{"entries":[{"placeholder":"cph_x","kind":"oauth_client_credentials","oauth":{"token_url":"u","client_secret":"s"}}]}`:             `entry 0 (cph_x): missing oauth.client_id`,
		`{"entries":[{"placeholder":"cph_x","kind":"oauth_client_credentials","oauth":{"token_url":"u","client_id":"i"}}]}`:                 `entry 0 (cph_x): missing oauth.client_secret`,
		`{"entries":[{"placeholder":"cph_a","secret":"","allowed_hosts":["h"]},{"placeholder":"cph_b","kind":"oauth_client_credentials"}]}`: `entry 1 (cph_b): missing oauth`,
	}
	for body, want := range cases {
		entries, err := DecodeIngestBody([]byte(body))
		if err == nil || err.Error() != want {
			t.Errorf("%s: err = %v, want %q", body, err, want)
		}
		if entries != nil {
			t.Errorf("%s: entries returned with an error", body)
		}
	}
}

// The handler answers 400 with the field named, so a control plane learns
// what to fix from the body alone.
func TestIngest_OAuthBadRequestNamesField(t *testing.T) {
	_, srv := ingestServer(t)
	body := `{"entries":[{"placeholder":"cph_x","kind":"oauth_client_credentials","oauth":{"token_url":"u","client_id":"i"}}]}`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/internal/maps/p-1", strings.NewReader(body))
	resp, err := srv.Client().Do(withIngestToken(req))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	msg, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(msg), "missing oauth.client_secret") {
		t.Fatalf("status %d body %q", resp.StatusCode, msg)
	}
}

// End to end over the wire: the client pushes an oauth entry, the handler
// stores a map whose resolver mints from the token endpoint, and the map
// substitutes the bare token toward the allowed host.
func TestIngest_OAuthEntryMintsThroughRegistry(t *testing.T) {
	reg, srv := ingestServer(t)
	ts := newTokenServer(t)
	c := NewClient(srv.URL).WithHTTPClient(srv.Client()).WithIngestToken("test-ingest-token")
	entry := IngestOAuthEntryFor("cph_o", IngestOAuth{TokenURL: ts.srv.URL, ClientID: "id", ClientSecret: "s", Scope: "read"}, []string{"api.example"})
	entry.SubstituteBody = true
	if err := c.PushMap(context.Background(), "p-1", []IngestEntry{
		entry,
		IngestEntryFor("cph_s", []byte("static"), []string{"api.example"}),
	}); err != nil {
		t.Fatal(err)
	}
	m, found := reg.Get("p-1")
	if !found || m.Empty() {
		t.Fatal("map not stored")
	}
	got, ok, err := m.SubstituteValueContext(context.Background(), "api.example", "Bearer cph_o cph_s")
	if err != nil || !ok || got != "Bearer tok-1 static" {
		t.Fatalf("got %q %v %v", got, ok, err)
	}
	// The context-free path leaves the oauth placeholder alone.
	if v, _ := m.SubstituteValue("api.example", "cph_o"); v != "cph_o" {
		t.Fatalf("static path resolved: %q", v)
	}
	ts.mu.Lock()
	scope := ts.form["scope"]
	ts.mu.Unlock()
	if scope != "read" {
		t.Fatalf("scope on the wire = %q", scope)
	}
	// The wire entry never carried a static secret.
	if entry.Secret != "" || entry.Kind != IngestKindOAuthClientCredentials {
		t.Fatalf("entry = %+v", entry)
	}
}
