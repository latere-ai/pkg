// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// newH2Upstream is an HTTP/2-capable TLS upstream: /echo records the auth header
// it received and echoes the negotiated protocol so a test can prove h2 rode all
// the way through.
func newH2Upstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		u.lastAuth = r.Header.Get("Authorization")
		fmt.Fprintf(w, "proto=%d auth=%s query=%s", r.ProtoMajor, r.Header.Get("Authorization"), r.URL.RawQuery)
	})
	// /trailer emits a response trailer (as gRPC-over-h2 status does) so the
	// gateway's trailer relay is exercised end to end.
	mux.HandleFunc("/trailer", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Trailer", "Grpc-Status")
		fmt.Fprint(w, "body")
		w.Header().Set("Grpc-Status", "0")
	})
	s := httptest.NewUnstartedServer(mux)
	s.EnableHTTP2 = true
	s.StartTLS()
	u.server = s
	t.Cleanup(s.Close)
	return u
}

// h2ClientThrough tunnels through the gateway and requires HTTP/2 on the inner
// leg: NextProtos advertises only h2, so if the gateway failed to offer h2 the
// handshake would fall back to http/1.1 and ProtoMajor assertions would catch it.
func h2ClientThrough(t *testing.T, proxyURL, token string, roots *x509.CertPool) *http.Client {
	t.Helper()
	pu, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:              http.ProxyURL(pu),
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {token}},
		TLSClientConfig:    &tls.Config{RootCAs: roots, NextProtos: []string{"h2"}},
		ForceAttemptHTTP2:  true,
	}}
}

// An HTTP/2 client negotiating h2 to a credential host still gets substitution:
// the upstream receives the real secret, the client only ever sent the
// placeholder, and the inner leg really spoke h2.
func TestGateway_H2SubstitutesForAllowedHost(t *testing.T) {
	up := newH2Upstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := h2ClientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/echo?api_key=cph_placeholder", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("inner leg did not negotiate h2: ProtoMajor=%d", resp.ProtoMajor)
	}
	body, _ := io.ReadAll(resp.Body)
	got := string(body)
	if !strings.Contains(got, "auth=Bearer sk-realsecret") {
		t.Fatalf("upstream did not receive real secret in header: %q", got)
	}
	if !strings.Contains(got, "query=api_key=sk-realsecret") {
		t.Fatalf("upstream did not receive real secret in query: %q", got)
	}
	if strings.Contains(got, "cph_placeholder") {
		t.Fatalf("placeholder reached upstream: %q", got)
	}
	// The client only ever transmitted the placeholder; the secret is added at
	// egress, so it is never present in what the workload sent.
	if req.Header.Get("Authorization") != "Bearer cph_placeholder" {
		t.Fatalf("client-side header mutated: %q", req.Header.Get("Authorization"))
	}
}

// A wrong-audience token over an h2-configured client is refused at CONNECT time:
// auth precedes TLS/ALPN, so the tunnel never establishes and no h2 is spoken.
func TestGateway_H2WrongAudRejected(t *testing.T) {
	up := newH2Upstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	// Only "Bearer allow" maps to a principal; the client presents a token that
	// is not registered (stands in for a wrong-aud / unverifiable JWT).
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := h2ClientThrough(t, proxy.URL, "Bearer wrong", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected the CONNECT to fail with 407")
	} else if !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "Proxy Authentication") {
		t.Fatalf("expected 407 proxy auth error, got %v", err)
	}
}

// An h2 client to a NON-credential host is a blind passthrough tunnel: TLS is
// end-to-end, so the upstream sees the placeholder unchanged and the gateway
// never decrypts the stream.
func TestGateway_H2PassthroughLeavesPlaceholder(t *testing.T) {
	up := newH2Upstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	// The secret is scoped to a different host, so this upstream is not inspected.
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{"api.provider.example"},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := h2ClientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("passthrough did not tunnel h2 end-to-end: ProtoMajor=%d", resp.ProtoMajor)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "auth=Bearer cph_placeholder") {
		t.Fatalf("passthrough should carry the placeholder verbatim: %q", body)
	}
	if strings.Contains(string(body), "realsecret") {
		t.Fatal("secret leaked on a non-allowed host over h2")
	}
}

// When the upstream round-trip fails on the h2 path, the stream carries a 502
// rather than a silent success.
func TestGateway_H2UpstreamFailureIs502(t *testing.T) {
	up := newH2Upstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	// UpstreamTLS trusts nothing, so the gateway's dial to the upstream fails
	// certificate verification and forward() returns an error.
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer allow": "p-1"}, UpstreamTLS: &tls.Config{RootCAs: x509.NewCertPool()}}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM())
	client := h2ClientThrough(t, proxy.URL, "Bearer allow", caPool)

	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("inner leg not h2: ProtoMajor=%d", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on upstream failure, got %d", resp.StatusCode)
	}
}

// Response trailers from the upstream are announced and relayed to the h2 client.
func TestGateway_H2RelaysTrailers(t *testing.T) {
	up := newH2Upstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := h2ClientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/trailer", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body) // trailers are populated only after the body is drained
	if string(body) != "body" {
		t.Fatalf("body: %q", body)
	}
	if got := resp.Trailer.Get("Grpc-Status"); got != "0" {
		t.Fatalf("trailer not relayed: Grpc-Status=%q trailer=%v", got, resp.Trailer)
	}
}

// Two requests multiplexed on one h2 connection each get correct per-stream
// substitution; forwarding state does not leak across streams.
func TestGateway_H2MultiStream(t *testing.T) {
	up := newH2Upstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := h2ClientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))

	for i := range 2 {
		req, _ := http.NewRequest("GET", fmt.Sprintf("%s/echo?api_key=cph_placeholder&n=%d", up.server.URL, i), nil)
		req.Header.Set("Authorization", "Bearer cph_placeholder")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if resp.ProtoMajor != 2 {
			resp.Body.Close()
			t.Fatalf("request %d not h2: ProtoMajor=%d", i, resp.ProtoMajor)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		got := string(body)
		if !strings.Contains(got, "auth=Bearer sk-realsecret") || !strings.Contains(got, "query=api_key=sk-realsecret") {
			t.Fatalf("request %d substitution wrong: %q", i, got)
		}
		if strings.Contains(got, "cph_placeholder") {
			t.Fatalf("request %d leaked placeholder upstream: %q", i, got)
		}
	}
}

// copyUpstreamResponse stops writing when the stream is gone, and never
// relays hop-by-hop headers.
func TestCopyUpstreamResponse_WriteFailureAndHopByHop(t *testing.T) {
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Connection": {"keep-alive"}, "X-Keep": {"yes"}},
		Body:       io.NopCloser(strings.NewReader("payload")),
	}
	w := &failingWriter{ResponseRecorder: httptest.NewRecorder()}
	copyUpstreamResponse(w, resp)
	if w.Header().Get("Connection") != "" {
		t.Fatal("hop-by-hop header relayed")
	}
	if w.Header().Get("X-Keep") != "yes" {
		t.Fatal("end-to-end header dropped")
	}
	if w.writes != 1 {
		t.Fatalf("expected the copy to stop after the first failed write, got %d writes", w.writes)
	}
}

// failingWriter rejects every body write, standing in for a closed h2 stream.
type failingWriter struct {
	*httptest.ResponseRecorder
	writes int
}

func (f *failingWriter) Write([]byte) (int, error) {
	f.writes++
	return 0, io.ErrClosedPipe
}
