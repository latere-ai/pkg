// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// upstream records the Authorization header it received and echoes request info.
type upstream struct {
	server   *httptest.Server
	lastAuth string
}

func newUpstream(t *testing.T) *upstream {
	t.Helper()
	u := &upstream{}
	mux := http.NewServeMux()
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		u.lastAuth = r.Header.Get("Authorization")
		fmt.Fprintf(w, "auth=%s query=%s", r.Header.Get("Authorization"), r.URL.RawQuery)
	})
	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		u.lastAuth = r.Header.Get("Authorization")
		fl, _ := w.(http.Flusher)
		w.Header().Set("Content-Type", "text/event-stream")
		for i := range 3 {
			fmt.Fprintf(w, "data: event-%d\n\n", i)
			if fl != nil {
				fl.Flush()
			}
		}
	})
	u.server = httptest.NewTLSServer(mux)
	t.Cleanup(u.server.Close)
	return u
}

func (u *upstream) host() string { return strings.TrimPrefix(u.server.URL, "https://") }

func (u *upstream) rootPool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(u.server.Certificate())
	return p
}

// hostIP returns the upstream's IP (loopback) for use as an allowed host.
func (u *upstream) hostIP(t *testing.T) string {
	t.Helper()
	return hostOnly(u.host())
}

// clientThrough builds an HTTP client that tunnels through the gateway with the
// given proxy-auth token and trusts the given roots for the inner TLS.
func clientThrough(t *testing.T, proxyURL string, token string, roots *x509.CertPool) *http.Client {
	t.Helper()
	pu, err := http.NewRequest("GET", proxyURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{
		Proxy:              http.ProxyURL(pu.URL),
		ProxyConnectHeader: http.Header{"Proxy-Authorization": {token}},
		TLSClientConfig:    &tls.Config{RootCAs: roots},
	}}
}

// bothRoots trusts the egress CA (for inspected leaves) and the upstream CA
// (for passthrough end-to-end TLS).
func bothRoots(ca *CA, up *upstream) *x509.CertPool {
	p := up.rootPool()
	block := ca.CertPEM()
	p.AppendCertsFromPEM(block)
	return p
}

func newGateway(t *testing.T, reg *Registry, ca *CA, up *upstream, auth Authenticator) *httptest.Server {
	t.Helper()
	gw := &Gateway{
		Registry:    reg,
		CA:          ca,
		Auth:        auth,
		UpstreamTLS: &tls.Config{RootCAs: up.rootPool()},
	}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)
	return proxy
}

// The positive path: the workload sends the placeholder; the upstream receives
// the real secret; the workload never learns it.
func TestGateway_SubstitutesForAllowedHost(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := clientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/echo?api_key=cph_placeholder", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
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
}

// The exfil path: a request to a host NOT on the credential's allow-list is a
// passthrough tunnel; the placeholder rides through unchanged, so the secret
// never leaves the gateway.
func TestGateway_PassthroughLeavesPlaceholder(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	// The secret is scoped to a different host, so the upstream is not inspected.
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{"api.provider.example"},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer deny": "p-1"})
	client := clientThrough(t, proxy.URL, "Bearer deny", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "auth=Bearer cph_placeholder") {
		t.Fatalf("passthrough should carry the placeholder verbatim: %q", body)
	}
	if strings.Contains(string(body), "realsecret") {
		t.Fatal("secret leaked on a non-allowed host")
	}
}

func TestGateway_RequiresProxyAuth(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	proxy := newGateway(t, NewRegistry(), ca, up, StaticAuth{})
	client := clientThrough(t, proxy.URL, "Bearer nope", bothRoots(ca, up))
	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected the CONNECT to fail with 407")
	}
	if !strings.Contains(err.Error(), "407") && !strings.Contains(err.Error(), "Proxy Authentication") {
		t.Fatalf("expected 407 proxy auth error, got %v", err)
	}
}

// The 407 names the configured realm, and the default when none is set.
func TestGateway_ProxyAuthenticateRealm(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	for realm, want := range map[string]string{"": DefaultRealm, "acme-egress": "acme-egress"} {
		gw := &Gateway{Registry: NewRegistry(), CA: ca, Auth: StaticAuth{}, Realm: realm}
		req := httptest.NewRequest(http.MethodConnect, "http://api.example.com:443", nil)
		req.Host = "api.example.com:443"
		rr := httptest.NewRecorder()
		gw.ServeHTTP(rr, req)
		if rr.Code != http.StatusProxyAuthRequired {
			t.Fatalf("realm %q: code=%d", realm, rr.Code)
		}
		if got := rr.Header().Get("Proxy-Authenticate"); got != `Bearer realm="`+want+`"` {
			t.Fatalf("realm %q: Proxy-Authenticate=%q", realm, got)
		}
	}
}

// SSE streams through the inspected path without buffering the body.
func TestGateway_SSEStreamsThrough(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})
	client := clientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))

	req, _ := http.NewRequest("GET", up.server.URL+"/sse", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.Header.Get("Content-Length") != "" {
		t.Fatal("SSE response should be streamed (no Content-Length)")
	}
	sc := bufio.NewScanner(resp.Body)
	var events int
	for sc.Scan() {
		if strings.HasPrefix(sc.Text(), "data: event-") {
			events++
		}
	}
	if events != 3 {
		t.Fatalf("expected 3 streamed events, got %d", events)
	}
	if up.lastAuth != "Bearer sk-realsecret" {
		t.Fatalf("SSE upstream auth: %q", up.lastAuth)
	}
}

// A non-CONNECT request to the proxy is rejected: the workload only ever tunnels.
func TestGateway_RejectsNonConnect(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	gw := &Gateway{Registry: NewRegistry(), CA: ca, Auth: StaticAuth{}, UpstreamTLS: &tls.Config{RootCAs: up.rootPool()}}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)
	resp, err := http.Get(proxy.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("non-CONNECT should be 405, got %d", resp.StatusCode)
	}
}

// A CONNECT to the gateway's own loopback must be refused before any dial, so
// an authenticated workload cannot tunnel to the in-process ingest API (SSRF)
// on a path that bypasses the network policy and any sidecar.
func TestGateway_RejectsLoopbackConnect(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	gw := &Gateway{Registry: NewRegistry(), CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}, BlockLoopbackTargets: true}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)

	for _, target := range []string{"127.0.0.1:9443", "localhost:9443", "[::1]:9443"} {
		pc, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(pc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer t\r\n\r\n", target, target)
		status, err := bufio.NewReader(pc).ReadString('\n')
		pc.Close()
		if err != nil {
			t.Fatalf("%s: reading status: %v", target, err)
		}
		if !strings.Contains(status, "403") {
			t.Fatalf("%s: loopback CONNECT should be 403, got %q", target, status)
		}
	}
}

func TestIsLoopbackTarget(t *testing.T) {
	cases := map[string]bool{
		"":              true,
		"LOCALHOST":     true,
		"127.0.0.1":     true,
		"127.8.8.8":     true,
		"::1":           true,
		"0.0.0.0":       true,
		"10.0.0.1":      false,
		"api.acme.test": false,
	}
	for host, want := range cases {
		if got := isLoopbackTarget(host); got != want {
			t.Errorf("isLoopbackTarget(%q) = %v want %v", host, got, want)
		}
	}
}

// When the upstream is unreachable/untrusted, the inspected path returns 502
// rather than a silent success.
func TestGateway_UpstreamFailureIs502(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_placeholder"),
		Secret:       []byte("sk-realsecret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	// UpstreamTLS trusts nothing, so the gateway's dial to the upstream fails
	// certificate verification.
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer allow": "p-1"}, UpstreamTLS: &tls.Config{RootCAs: x509.NewCertPool()}}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)
	// The client trusts only the egress CA (for the inner inspected leg).
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM())
	client := clientThrough(t, proxy.URL, "Bearer allow", caPool)

	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected 502 on upstream failure, got %d", resp.StatusCode)
	}
}

func TestHostOnlyAndWithPort(t *testing.T) {
	if hostOnly("api.example.com:443") != "api.example.com" {
		t.Fatal("hostOnly should strip port")
	}
	if hostOnly("api.example.com") != "api.example.com" {
		t.Fatal("hostOnly bare host unchanged")
	}
	if withPort("api.example.com") != "api.example.com:443" {
		t.Fatal("withPort should default to 443")
	}
	if withPort("api.example.com:8443") != "api.example.com:8443" {
		t.Fatal("withPort should keep an explicit port")
	}
}

// withPort keeps an explicit port, appends 443 to a bare host, and hostOnly
// of the result never panics.
func FuzzWithPort(f *testing.F) {
	f.Add("api.example.com")
	f.Add("api.example.com:8443")
	f.Add("[::1]:443")
	f.Fuzz(func(t *testing.T, hostport string) {
		hp := withPort(hostport)
		_ = hostOnly(hp)
		if _, _, err := net.SplitHostPort(hostport); err == nil && hp != hostport {
			t.Fatalf("withPort(%q) = %q changed an explicit port", hostport, hp)
		}
		if !strings.ContainsAny(hostport, ":[]") && hp != hostport+":443" {
			t.Fatalf("withPort(%q) = %q want default port", hostport, hp)
		}
	})
}

// A passthrough tunnel relays the upstream's close to the client: a client
// waiting on a close-delimited response sees EOF instead of hanging.
func TestGateway_PassthroughPropagatesUpstreamClose(t *testing.T) {
	// Raw TCP upstream: reads one byte, writes a response, closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 1)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("response-then-close"))
		c.Close()
	}()

	ca, _, _, _ := GenerateCA("")
	gw := &Gateway{Registry: NewRegistry(), CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)

	pc, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	target := ln.Addr().String()
	fmt.Fprintf(pc, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer t\r\n\r\n", target, target)
	br := bufio.NewReader(pc)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CONNECT response: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	if _, err := pc.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	// The client keeps its write side open: EOF must come from the upstream's
	// close being relayed through the gateway, not from the client giving up.
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("expected EOF after upstream close, got %v", err)
	}
	if !strings.Contains(string(data), "response-then-close") {
		t.Fatalf("tunnel data: %q", data)
	}
}

// Bytes a client pipelines in the same segment as the CONNECT head (before
// reading the 200) land in the HTTP server's read buffer; the tunnel must
// deliver them to the upstream rather than silently dropping them.
func TestGateway_ConnectPipelinedBytesReachUpstream(t *testing.T) {
	// Raw TCP upstream: echoes the first 5 bytes it receives, then closes.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write(append([]byte("GOT:"), buf...))
		}
		c.Close()
	}()

	ca, _, _, _ := GenerateCA("")
	gw := &Gateway{Registry: NewRegistry(), CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)

	pc, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	target := ln.Addr().String()
	// CONNECT head and the tunnel payload in ONE write, before reading the 200.
	head := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Bearer t\r\n\r\n", target, target)
	if _, err := pc.Write([]byte(head + "EARLY")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(pc)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("reading CONNECT response: %v", err)
		}
		if line == "\r\n" {
			break
		}
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(br)
	if err != nil {
		t.Fatalf("reading echo: %v", err)
	}
	if string(data) != "GOT:EARLY" {
		t.Fatalf("pipelined bytes lost: upstream echoed %q, want %q", data, "GOT:EARLY")
	}
}

// Passthrough to an unreachable non-allowed host surfaces the dial failure path
// without crashing (the workload's tunnel simply closes).
func TestGateway_PassthroughDialFailure(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{Placeholder: []byte("cph_x"), Secret: []byte("s"), AllowedHosts: []string{"api.provider.example"}}})
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM())
	client := clientThrough(t, proxy.URL, "Bearer t", caPool)
	// 127.0.0.1:1 is not allow-listed (so passthrough) and refuses connections.
	req, _ := http.NewRequest("GET", "https://127.0.0.1:1/", nil)
	resp, err := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil {
		t.Fatal("expected the tunnel to fail to an unreachable upstream")
	}
}

// A ResponseWriter that can't be hijacked yields 500 (CONNECT needs a raw conn).
func TestGateway_HijackUnsupported(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	gw := &Gateway{Registry: NewRegistry(), CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}}
	req := httptest.NewRequest(http.MethodConnect, "http://api.example.com:443", nil)
	req.Host = "api.example.com:443"
	req.Header.Set("Proxy-Authorization", "Bearer t")
	rr := httptest.NewRecorder() // httptest.ResponseRecorder is not an http.Hijacker
	gw.ServeHTTP(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("non-hijackable writer should yield 500, got %d", rr.Code)
	}
}

// A gateway with Log set exercises log()'s non-default branch during a
// passthrough dial failure.
func TestGateway_LogWhenSet(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{Placeholder: []byte("cph_x"), Secret: []byte("s"), AllowedHosts: []string{"api.provider.example"}}})
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	ts := httptest.NewServer(gw)
	t.Cleanup(ts.Close)
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM())
	client := clientThrough(t, ts.URL, "Bearer t", caPool)
	req, _ := http.NewRequest("GET", "https://127.0.0.1:1/", nil) // not allow-listed -> passthrough -> dial fail -> warn
	resp, _ := client.Do(req)
	if resp != nil {
		defer resp.Body.Close()
	}
}

// When the workload sends non-TLS bytes after CONNECT to an inspected host, the
// gateway's inner TLS handshake fails and it closes the tunnel.
func TestGateway_MITMHandshakeFailure(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{Placeholder: []byte("cph_x"), Secret: []byte("s"), AllowedHosts: []string{"api.provider.example"}}})
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}}
	ts := httptest.NewServer(gw)
	t.Cleanup(ts.Close)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT api.provider.example:443 HTTP/1.1\r\nHost: api.provider.example:443\r\nProxy-Authorization: Bearer t\r\n\r\n")
	br := bufio.NewReader(conn)
	status, _ := br.ReadString('\n')
	if !strings.Contains(status, "200") {
		t.Fatalf("expected 200 Connection Established, got %q", status)
	}
	_, _ = br.ReadString('\n') // blank line
	// Garbage instead of a TLS ClientHello -> inner handshake fails, gateway closes.
	_, _ = conn.Write([]byte("this-is-not-tls\r\n\r\n"))
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 8)
	if _, err := conn.Read(buf); err == nil {
		// A successful read is fine too as long as the tunnel then closes; try once more.
		if _, err2 := conn.Read(buf); err2 == nil {
			t.Fatal("expected the gateway to close the tunnel after a failed handshake")
		}
	}
}

// A leaf mint failure on the inspected path is logged and the tunnel closes.
func TestGateway_MITMLeafMintFailure(t *testing.T) {
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{Placeholder: []byte("cph_x"), Secret: []byte("s"), AllowedHosts: []string{"api.provider.example"}}})
	ca.keygen = func() (*ecdsa.PrivateKey, error) { return nil, errors.New("no keys") }
	logs := &syncBuffer{}
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}, Log: slog.New(slog.NewTextHandler(logs, nil))}
	ts := httptest.NewServer(gw)
	t.Cleanup(ts.Close)

	conn, err := net.Dial("tcp", ts.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	fmt.Fprint(conn, "CONNECT api.provider.example:443 HTTP/1.1\r\nHost: api.provider.example:443\r\nProxy-Authorization: Bearer t\r\n\r\n")
	br := bufio.NewReader(conn)
	if status, _ := br.ReadString('\n'); !strings.Contains(status, "200") {
		t.Fatalf("expected 200 Connection Established, got %q", status)
	}
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.ReadAll(br) // the gateway closes without a handshake
	deadline := time.Now().Add(3 * time.Second)
	for !strings.Contains(logs.String(), "egress leaf mint") {
		if time.Now().After(deadline) {
			t.Fatalf("leaf mint failure not logged: %q", logs.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// syncBuffer is a mutex-guarded log sink: the handler goroutine writes it
// while the test reads it, and the lock is what orders the two.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Covers the two reachable inspected-loop branches: a Connection: close
// request exits the keep-alive loop, and a malformed request after a
// successful inner handshake makes http.ReadRequest fail.
func TestGateway_MITMCloseAndBadRequest(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{Placeholder: []byte("cph_placeholder"), Secret: []byte("sk"), AllowedHosts: []string{up.hostIP(t)}}})
	proxy := newGateway(t, reg, ca, up, StaticAuth{"Bearer allow": "p-1"})

	// (a) Connection: close -> gateway returns after one request.
	client := clientThrough(t, proxy.URL, "Bearer allow", bothRoots(ca, up))
	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Close = true
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("close request: %v", err)
	}
	_ = resp.Body.Close()

	// (b) Complete the inner TLS handshake, then send a malformed request line
	// so http.ReadRequest errors and the tunnel closes.
	raw, err := net.Dial("tcp", strings.TrimPrefix(proxy.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	fmt.Fprintf(raw, "CONNECT %s HTTP/1.1\r\nProxy-Authorization: Bearer allow\r\n\r\n", up.host())
	brd := bufio.NewReader(raw)
	if line, _ := brd.ReadString('\n'); !strings.Contains(line, "200") {
		t.Fatalf("CONNECT not established: %q", line)
	}
	_, _ = brd.ReadString('\n') // blank line
	egressPool := x509.NewCertPool()
	egressPool.AppendCertsFromPEM(ca.CertPEM())
	tc := tls.Client(raw, &tls.Config{ServerName: up.hostIP(t), RootCAs: egressPool})
	if err := tc.Handshake(); err != nil {
		t.Fatalf("inner TLS handshake: %v", err)
	}
	_, _ = tc.Write([]byte("NOTAVALIDREQUESTLINE\r\n\r\n"))
	_ = tc.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.ReadAll(tc) // gateway returns on ReadRequest error; conn closes
}

// The egress-control contract, end to end: for a substituted host the workload
// receives the real secret; for a passthrough host the placeholder rides
// through unchanged. These automate the production smoke so a regression that
// breaks egress is caught in CI.

// A substituted host receives the real secret; the workload only ever held the
// placeholder, and it validates the gateway's leaf against the egress CA.
func TestEgressControl_SubstitutedHostGetsRealSecret(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_live"),
		Secret:       []byte("sk-real-secret"),
		AllowedHosts: []string{up.hostIP(t)},
	}})
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}, UpstreamTLS: upstreamRoots(up)}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)

	// The workload trusts the egress CA for the inspected leaf.
	trust := x509.NewCertPool()
	trust.AppendCertsFromPEM(ca.CertPEM())
	client := clientThrough(t, proxy.URL, "Bearer t", trust)

	body := doGet(t, client, up.server.URL+"/echo?api_key=cph_live", "Bearer cph_live")
	if !strings.Contains(body, "auth=Bearer sk-real-secret") || strings.Contains(body, "cph_live") {
		t.Fatalf("substituted host did not receive the real secret: %q", body)
	}
}

// The regression guard for the CA-trust bug: a workload routes ALL egress
// through the gateway, so for a passthrough (non-substituted) host it still
// terminates TLS directly against the host's real public certificate. If the
// workload trusts ONLY the egress CA, that handshake fails and the workload
// cannot reach any non-substituted host. The workload MUST trust public roots
// + the egress CA combined. This test asserts both halves.
func TestEgressControl_PassthroughNeedsPublicRoots(t *testing.T) {
	up := newUpstream(t) // a passthrough host with a real (public-style) cert
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	// Scope the secret to a different host, so `up` is passthrough, not inspected.
	reg.Set("p-1", []Entry{{
		Placeholder:  []byte("cph_live"),
		Secret:       []byte("sk-real-secret"),
		AllowedHosts: []string{"api.provider.example"},
	}})
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}}
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)

	// Egress-CA-only trust (the bug) cannot validate the passthrough host's real
	// cert: the handshake fails.
	egressOnly := x509.NewCertPool()
	egressOnly.AppendCertsFromPEM(ca.CertPEM())
	bad := clientThrough(t, proxy.URL, "Bearer t", egressOnly)
	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_live")
	badResp, err := bad.Do(req)
	if badResp != nil {
		defer badResp.Body.Close()
	}
	if err == nil {
		t.Fatal("egress-CA-only trust must fail to reach a passthrough host; the workload needs public roots too")
	}

	// Combined trust (public roots + egress CA) reaches it, and the placeholder
	// rides through unchanged: a non-allowed host learns nothing.
	combined := x509.NewCertPool()
	combined.AppendCertsFromPEM(ca.CertPEM())
	combined.AddCert(up.server.Certificate())
	good := clientThrough(t, proxy.URL, "Bearer t", combined)
	body := doGet(t, good, up.server.URL+"/echo", "Bearer cph_live")
	if !strings.Contains(body, "auth=Bearer cph_live") || strings.Contains(body, "sk-real-secret") {
		t.Fatalf("passthrough should carry the placeholder unchanged: %q", body)
	}
}

func upstreamRoots(ups ...*upstream) *tls.Config {
	p := x509.NewCertPool()
	for _, u := range ups {
		p.AddCert(u.server.Certificate())
	}
	return &tls.Config{RootCAs: p}
}

func doGet(t *testing.T, c *http.Client, url, auth string) string {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", auth)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("request to %s failed: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}
