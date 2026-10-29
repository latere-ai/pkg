// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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

// Over HTTP/2 the request's :authority is its Host: one naming another
// authority than the tunnel's is refused 421 on its stream.
func TestGateway_H2MisdirectedAuthorityIsRefused(t *testing.T) {
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

	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Host = "other.example"
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 {
		t.Fatalf("inner leg did not negotiate h2: ProtoMajor=%d", resp.ProtoMajor)
	}
	if resp.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status = %d, want 421", resp.StatusCode)
	}
	if up.lastAuth != "" {
		t.Fatalf("a misdirected request reached the upstream with %q", up.lastAuth)
	}
}

// An HTTP/1.1 client to a credential host whose upstream speaks HTTP/2 reads
// an HTTP/1.1 status line: the gateway answers in the protocol the workload
// spoke, not the one the upstream answered in. A strict client, such as Bun's,
// refuses a response whose status line names HTTP/2.0 on an HTTP/1.1
// connection.
func TestGateway_H1ClientReadsH1FromAnH2Upstream(t *testing.T) {
	up := newH2Upstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	pu, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: &http.Transport{
		Proxy:              http.ProxyURL(pu),
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer allow"}},
		TLSClientConfig:    &tls.Config{RootCAs: bothRoots(ca, up), NextProtos: []string{"http/1.1"}},
	}}
	for _, path := range []string{"/echo", "/trailer"} {
		req, _ := http.NewRequest("GET", up.server.URL+path, nil)
		req.Header.Set("Authorization", "Bearer cph_placeholder")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: request: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.Proto != "HTTP/1.1" {
			t.Fatalf("%s: the status line names %s, want HTTP/1.1", path, resp.Proto)
		}
		if path == "/echo" && !strings.Contains(string(body), "proto=2 auth=Bearer sk-realsecret") {
			t.Fatalf("%s: the upstream did not answer over h2 with the secret: %q", path, body)
		}
		if path == "/trailer" && string(body) != "body" {
			t.Fatalf("%s: body %q", path, body)
		}
	}
}

// A streamed answer from an HTTP/2 upstream, which carries no length, reaches
// an HTTP/1.1 client framed so the client knows where it ends: an event
// stream a model sends is read to its end, and the next request on the same
// connection is served. Unframed, the client would wait for the connection to
// close while the gateway waited for its next request.
func TestGateway_H1ClientReadsAStreamFromAnH2Upstream(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/stream", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for _, part := range []string{"data: a\n\n", "data: b\n\n"} {
			_, _ = io.WriteString(w, part)
			w.(http.Flusher).Flush()
		}
	})
	s := httptest.NewUnstartedServer(mux)
	s.EnableHTTP2 = true
	s.StartTLS()
	t.Cleanup(s.Close)
	up := &upstream{server: s}
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{Placeholder: []byte("cph_placeholder"), Secret: []byte("sk-realsecret"), AllowedHosts: []string{up.hostIP(t)}}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	pu, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Proxy:              http.ProxyURL(pu),
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {"Bearer allow"}},
		TLSClientConfig:    &tls.Config{RootCAs: bothRoots(ca, up), NextProtos: []string{"http/1.1"}},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			dials.Add(1)
			var d net.Dialer
			return d.DialContext(ctx, network, address)
		},
	}}
	for i := range 2 {
		resp, err := client.Get(s.URL + "/stream")
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("request %d: reading the stream: %v", i, err)
		}
		if string(body) != "data: a\n\ndata: b\n\n" || resp.Proto != "HTTP/1.1" {
			t.Fatalf("request %d: %s with %q", i, resp.Proto, body)
		}
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("the client dialed the gateway %d times, want one connection kept alive", got)
	}
}

// TestBodyAllowed keeps a chunked framing off the statuses that carry no body.
func TestBodyAllowed(t *testing.T) {
	for status, want := range map[int]bool{100: false, 200: true, 204: false, 206: true, 304: false, 404: true, 502: true} {
		if got := bodyAllowed(status); got != want {
			t.Errorf("bodyAllowed(%d) = %v, want %v", status, got, want)
		}
	}
}
