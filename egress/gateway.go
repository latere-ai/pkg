// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/http2"
)

// DefaultRealm is the Proxy-Authenticate realm a Gateway answers 407 with
// when none is configured.
const DefaultRealm = "egress"

// Authenticator maps a CONNECT request's Proxy-Authorization header to a
// principal. The production implementation verifies a per-workload JWT
// against the issuer's JWKS ([TokenAuth]); tests use a static map. Returning
// ok=false yields a 407.
type Authenticator interface {
	Authenticate(proxyAuthorization string) (principal string, ok bool)
}

// StaticAuth is a trivial Authenticator for tests and local runs: it maps a full
// Proxy-Authorization header value to a principal.
type StaticAuth map[string]string

// Authenticate implements Authenticator.
func (s StaticAuth) Authenticate(h string) (string, bool) {
	id, ok := s[strings.TrimSpace(h)]
	return id, ok
}

// Gateway is the TLS-terminating egress substitution proxy. It accepts HTTPS
// CONNECT tunnels from workloads, terminates TLS for hosts that have a bound
// secret (minting a CA-signed leaf per SNI), substitutes placeholders for real
// secrets in the request, and streams the upstream response back untouched.
// Hosts with no bound secret are passthrough tunnels the gateway never decrypts.
type Gateway struct {
	Registry *Registry
	CA       *CA
	Auth     Authenticator
	// UpstreamTLS configures dialing real upstreams. nil uses the system roots;
	// tests point RootCAs at a test upstream's CA.
	UpstreamTLS *tls.Config
	// BlockLoopbackTargets refuses CONNECT to the gateway's own loopback so an
	// authenticated workload cannot tunnel to in-process listeners (e.g. the
	// ingest API) on a path the network policy and any sidecar never see. The
	// production binary sets it; it defaults off so embedders and tests that
	// colocate upstreams on loopback keep working.
	BlockLoopbackTargets bool
	// Realm is the Proxy-Authenticate realm on a 407. Empty means DefaultRealm.
	Realm string
	Log   *slog.Logger

	once      sync.Once
	transport *http.Transport
}

func (g *Gateway) log() *slog.Logger {
	if g.Log != nil {
		return g.Log
	}
	return slog.Default()
}

func (g *Gateway) realm() string {
	if g.Realm != "" {
		return g.Realm
	}
	return DefaultRealm
}

func (g *Gateway) tr() *http.Transport {
	g.once.Do(func() {
		g.transport = &http.Transport{
			TLSClientConfig:     g.UpstreamTLS,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        100,
			IdleConnTimeout:     90e9,
			TLSHandshakeTimeout: 10e9,
		}
	})
	return g.transport
}

// ServeHTTP handles the proxy protocol. Only CONNECT is supported (the workload
// is configured with HTTPS_PROXY, so all egress arrives as CONNECT tunnels).
func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "egress gateway accepts CONNECT only", http.StatusMethodNotAllowed)
		return
	}
	g.handleConnect(w, r)
}

func (g *Gateway) handleConnect(w http.ResponseWriter, r *http.Request) {
	principal, ok := g.Auth.Authenticate(r.Header.Get("Proxy-Authorization"))
	if !ok {
		w.Header().Set("Proxy-Authenticate", `Bearer realm="`+g.realm()+`"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	host := hostOnly(r.Host)
	// Reject CONNECT to the gateway's own loopback interface. Such a target would
	// dial from inside the gateway's own network namespace, bypassing any
	// sidecar and network policy, and could tunnel straight to the in-process
	// ingest API (a server-side request forgery onto PUT/DELETE /internal/maps).
	if g.BlockLoopbackTargets && isLoopbackTarget(host) {
		http.Error(w, "egress gateway: loopback target not allowed", http.StatusForbidden)
		return
	}
	m, _ := g.Registry.Get(principal)
	inspect := m.HostHasSecret(host)

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// Bytes the client pipelined after the CONNECT head (e.g. an eager TLS
	// ClientHello sent before reading the 200) sit in the server's read
	// buffer; feed them into the tunnel ahead of the socket.
	if n := rw.Reader.Buffered(); n > 0 {
		early, err := rw.Peek(n)
		if err != nil {
			return
		}
		client = &prefixedConn{Conn: client, r: io.MultiReader(bytes.NewReader(early), client)}
	}

	// Both tunnel halves run to completion inside this handler, so the
	// request context is still live and scopes the upstream dial and the
	// TLS handshake.
	if inspect {
		g.mitm(r.Context(), client, r.Host, m)
		return
	}
	g.passthrough(r.Context(), client, r.Host)
}

// prefixedConn reads first from bytes already consumed into the HTTP server's
// buffer, then from the connection itself. Writes, Close, and deadline methods
// pass through to the underlying conn.
type prefixedConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// passthrough splices the workload connection to the real upstream without
// terminating TLS. The gateway never sees plaintext for these hosts.
func (g *Gateway) passthrough(ctx context.Context, client net.Conn, hostport string) {
	var d net.Dialer
	up, err := d.DialContext(ctx, "tcp", withPort(hostport))
	if err != nil {
		g.log().WarnContext(ctx, "egress passthrough dial", "host", hostport, "err", err)
		return
	}
	// Close both ends as soon as either direction finishes so a FIN from
	// either side tears down the whole tunnel (standard CONNECT semantics).
	// Double Close on a net.Conn is safe.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(up, client)
		_ = up.Close()
		_ = client.Close()
	}()
	_, _ = io.Copy(client, up)
	_ = up.Close()
	_ = client.Close()
	<-done
}

// mitm terminates the workload's TLS with a CA-signed leaf and offers ALPN so
// the client can pick HTTP/2 or HTTP/1.1. The negotiated protocol chooses the
// serve path; both apply the same substitution + upstream-forward core,
// differing only in framing. hostport is the CONNECT authority (host:port):
// the bare host drives leaf minting and substitution scoping, the full
// host:port drives the upstream dial.
func (g *Gateway) mitm(ctx context.Context, client net.Conn, hostport string, m *Map) {
	host := hostOnly(hostport)
	tc, err := g.CA.leafFor(host)
	if err != nil {
		g.log().WarnContext(ctx, "egress leaf mint", "host", host, "err", err)
		return
	}
	serverConf := &tls.Config{
		Certificates: []tls.Certificate{{
			Certificate: tc.Certificate,
			PrivateKey:  tc.PrivateKey,
			Leaf:        tc.Leaf,
		}},
		// Offer h2 so a client that requires HTTP/2 to a credential host still
		// negotiates a protocol the gateway terminates and substitutes over.
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsClient := tls.Server(client, serverConf)
	if err := tlsClient.HandshakeContext(ctx); err != nil {
		return
	}
	defer func() { _ = tlsClient.Close() }()

	if tlsClient.ConnectionState().NegotiatedProtocol == "h2" {
		g.mitmH2(tlsClient, host, hostport, m)
		return
	}
	g.mitmH1(tlsClient, host, hostport, m)
}

// forward substitutes placeholders in req (scoped to host) and round-trips it to
// the real upstream over the shared transport. The HTTP/1.1 loop and each HTTP/2
// stream both call it, so the substitution core is identical across framings.
func (g *Gateway) forward(host, hostport string, req *http.Request, m *Map) (*http.Response, error) {
	req.URL.Scheme = "https"
	req.URL.Host = hostport
	req.RequestURI = ""
	SubstituteHTTPRequest(host, req, m)
	return g.tr().RoundTrip(req)
}

// mitmH1 serves the workload's HTTP/1.1 requests, looping for keep-alive. Each
// request is substituted and forwarded; the response streams back byte-for-byte
// (SSE-safe: no buffering).
func (g *Gateway) mitmH1(tlsClient *tls.Conn, host, hostport string, m *Map) {
	br := bufio.NewReader(tlsClient)
	for {
		req, err := http.ReadRequest(br)
		if err != nil {
			return // EOF or client closed
		}
		resp, err := g.forward(host, hostport, req, m)
		if err != nil {
			writeGatewayError(tlsClient)
			return
		}
		werr := resp.Write(tlsClient)
		_ = resp.Body.Close()
		if werr != nil || req.Close || resp.Close {
			return
		}
	}
}

// mitmH2 serves the workload's HTTP/2 connection. Each stream is delivered as a
// decoded *http.Request to the handler, which applies the same substitution core
// as mitmH1 and copies the upstream response (status, headers, streamed body,
// trailers) back. http2.Server multiplexes streams over the one connection and
// runs the handler per stream, so forwarding state never crosses streams.
func (g *Gateway) mitmH2(tlsClient *tls.Conn, host, hostport string, m *Map) {
	h := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		resp, err := g.forward(host, hostport, req, m)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		copyUpstreamResponse(w, resp)
	})
	(&http2.Server{}).ServeConn(tlsClient, &http2.ServeConnOpts{Handler: h})
}

// hopByHopHeaders are connection-scoped and must not be relayed from an upstream
// response onto an HTTP/2 stream, whose framing manages them itself.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Transfer-Encoding",
	"Upgrade",
}

// copyUpstreamResponse writes an upstream response to an HTTP/2 stream: it
// forwards end-to-end headers, streams the body with a flush per chunk (SSE-safe),
// and relays trailers (where gRPC-over-h2 status rides).
func copyUpstreamResponse(w http.ResponseWriter, resp *http.Response) {
	if len(resp.Trailer) > 0 {
		w.Header().Set("Trailer", strings.Join(slices.Collect(maps.Keys(resp.Trailer)), ", "))
	}
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	for _, h := range hopByHopHeaders {
		w.Header().Del(h)
	}
	w.WriteHeader(resp.StatusCode)

	fl, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
		}
		if rerr != nil {
			break
		}
	}
	for k, vals := range resp.Trailer {
		for _, v := range vals {
			w.Header().Add(http.TrailerPrefix+k, v)
		}
	}
}

func writeGatewayError(w io.Writer) {
	_, _ = io.WriteString(w, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}

// isLoopbackTarget reports whether host names the local loopback (an IP in
// 127.0.0.0/8 or ::1, the unspecified address, or the literal "localhost"). Such
// a CONNECT target would reach the gateway's own listeners on a path the
// network policy and any sidecar cannot see.
func isLoopbackTarget(host string) bool {
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	return false
}

// hostOnly strips a :port from a host[:port] value.
func hostOnly(hostport string) string {
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		return h
	}
	return hostport
}

// withPort ensures a host has a port, defaulting to 443.
func withPort(hostport string) string {
	if _, _, err := net.SplitHostPort(hostport); err == nil {
		return hostport
	}
	return net.JoinHostPort(hostport, "443")
}
