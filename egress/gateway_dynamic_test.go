// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"io"
	"net/http"
	"strings"
	"testing"
)

// End to end through the CONNECT proxy: the workload sends "Bearer <placeholder>",
// the resolver mints a token from the token endpoint, and the upstream receives
// "Bearer <token>". When the token endpoint is down and nothing is cached the
// request fails at the gateway with 502 and the placeholder never leaves.
func TestGateway_DynamicCredential(t *testing.T) {
	up := newUpstream(t)
	ts := newTokenServer(t)
	cc := &OAuthClientCredentials{TokenURL: ts.srv.URL, ClientID: "id", ClientSecret: "s", HTTPClient: ts.srv.Client()}
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		AllowedHosts: []string{up.hostIP(t)},
		Resolve:      cc.Resolve,
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := clientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "auth=Bearer tok-1") {
		t.Fatalf("upstream did not receive the minted token: %q", body)
	}

	// A fresh entry with a dead token endpoint: nothing cached, so 502.
	ts.respond(http.StatusInternalServerError, "down")
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		AllowedHosts: []string{up.hostIP(t)},
		Resolve:      (&OAuthClientCredentials{TokenURL: ts.srv.URL, HTTPClient: ts.srv.Client()}).Resolve,
	}})
	up.lastAuth = ""
	// A tunnel keeps the map it was opened with, so open a new one.
	client = clientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))
	req, _ = http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
	if up.lastAuth != "" {
		t.Fatalf("request reached upstream with %q", up.lastAuth)
	}
}
