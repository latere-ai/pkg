// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"

	"latere.ai/x/pkg/hostmatch"
)

// The egress proxy's time limits: reaching a destination, and reading a
// request's header from the stage.
const (
	egressDialTimeout   = 10 * time.Second
	egressHeaderTimeout = 30 * time.Second
)

// errLocalDestination is a destination on this machine or its link: the
// host's own services, or a cloud's metadata endpoint.
var errLocalDestination = errors.New("the destination is this machine or its link-local network")

// egress is the proxy a stage with a network allowlist reaches the network
// through under Seatbelt. The stage's profile lets it connect to this
// proxy's loopback port and nowhere else, and the proxy admits a request by
// the host and port it names: a CONNECT's target, or a plain request's
// absolute URL. A host the allowlist names alone is admitted for a CONNECT
// to port 443 and a plain request to port 80; one it names as host:port is
// admitted on that port alone. Any other port is refused, so an allowed host
// is not a tunnel to its SSH or database port.
// It never terminates TLS and holds no certificate authority: a tunnel
// carries the client's own TLS end to end, so the proxy learns the host it
// is asked for and nothing of what passes through.
//
// A destination on this machine or its link-local network is refused even
// when its name is allowed, and is checked on the address the name resolves
// to, so a name an attacker points at 127.0.0.1 does not reach a service
// the host runs.
type egress struct {
	// standard admits the hosts named without a port, on the standard
	// ports; byPort admits the hosts named with a port, on that port.
	standard hostmatch.Matcher
	byPort   map[string]hostmatch.Matcher
	// dial reaches a destination; forward carries a plain request.
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	forward http.RoundTripper
	// notice receives one line for each refusal. The launcher passes the
	// stage's own log, so whoever reads the stage's output sees why a
	// connection failed.
	notice io.Writer
}

// newEgress builds the proxy for an allowlist. localOK admits destinations
// on this machine, which only this package's tests do.
func newEgress(domains []string, notice io.Writer, localOK bool) *egress {
	dialer := &net.Dialer{Timeout: egressDialTimeout, KeepAlive: 30 * time.Second}
	if !localOK {
		dialer.Control = refuseLocal
	}
	plain, byPort := splitAllowlist(domains)
	e := &egress{standard: hostmatch.New(plain, normalizeHost), byPort: map[string]hostmatch.Matcher{}, dial: dialer.DialContext, notice: notice}
	for port, hosts := range byPort {
		e.byPort[port] = hostmatch.New(hosts, normalizeHost)
	}
	// The transport carries plain http only, and adds nothing to what the
	// stage sends: no trace header, no compression it did not ask for.
	e.forward = &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return e.dial(ctx, network, address)
		},
		DisableCompression:    true,
		MaxIdleConns:          16,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
	}
	return e
}

// refuseLocal is the dialer's check of the address a name resolved to, made
// before the connection is opened.
func refuseLocal(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("check destination %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return fmt.Errorf("%w: %s", errLocalDestination, host)
	}
	return nil
}

// normalizeHost is the form a host and an allowlist entry are compared in:
// trimmed, lower case, without a trailing dot.
func normalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
}

// The standard ports: a CONNECT carries TLS to 443, a plain request goes to
// 80.
const (
	tunnelPort = "443"
	plainPort  = "80"
)

// splitAllowlist sorts allowlist entries into hosts named alone and hosts
// named with a port, by port. An entry whose port is not a number from 1 to
// 65535 admits nothing.
func splitAllowlist(domains []string) ([]string, map[string][]string) {
	var plain []string
	byPort := map[string][]string{}
	for _, entry := range domains {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		host, port, err := net.SplitHostPort(entry)
		if err != nil {
			// No port: a host alone, an IPv6 address among them.
			plain = append(plain, entry)
			continue
		}
		if canonical, ok := portNumber(port); ok {
			byPort[canonical] = append(byPort[canonical], host)
		}
	}
	return plain, byPort
}

// portNumber is a port in its canonical decimal form, if it is one.
func portNumber(port string) (string, bool) {
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	return strconv.Itoa(n), true
}

// admits reports whether the allowlist admits host on port, for a CONNECT
// when tunnel is true and a plain request otherwise.
func (e *egress) admits(host, port string, tunnel bool) bool {
	host = normalizeHost(host)
	port, ok := portNumber(port)
	if !ok {
		return false
	}
	if matcher, ok := e.byPort[port]; ok && matcher.Matches(host) {
		return true
	}
	standard := plainPort
	if tunnel {
		standard = tunnelPort
	}
	return port == standard && e.standard.Matches(host)
}

// refuse answers a request for a host and port the allowlist does not
// admit, and says so in the stage's log.
func (e *egress) refuse(w http.ResponseWriter, host, port string) {
	target := net.JoinHostPort(host, port)
	if e.notice != nil {
		_, _ = fmt.Fprintf(e.notice, "hostsandbox: refused a connection to %s, which is not on this stage's network allowlist\n", target)
	}
	http.Error(w, "hostsandbox: "+target+" is not on this stage's network allowlist", http.StatusForbidden)
}

func (e *egress) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		e.tunnel(w, r)
		return
	}
	if r.URL.Scheme != "http" || r.URL.Host == "" {
		http.Error(w, "hostsandbox: this proxy carries a CONNECT or a request for an absolute http URL", http.StatusBadRequest)
		return
	}
	host, port := r.URL.Hostname(), r.URL.Port()
	if port == "" {
		port = plainPort
	}
	if !e.admits(host, port, false) {
		e.refuse(w, host, port)
		return
	}
	out := r.Clone(r.Context())
	out.RequestURI = ""
	dropHopHeaders(out.Header)
	response, err := e.forward.RoundTrip(out)
	if err != nil {
		http.Error(w, "hostsandbox: could not reach "+host+": "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = response.Body.Close() }()
	dropHopHeaders(response.Header)
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	// A copy cut short is the stage's or the destination's connection
	// ending; there is no one left to tell.
	_, _ = io.Copy(w, response.Body)
}

// tunnel connects a CONNECT to its target and splices the two connections.
func (e *egress) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "hostsandbox: a CONNECT names a host and a port", http.StatusBadRequest)
		return
	}
	if !e.admits(host, port, true) {
		e.refuse(w, host, port)
		return
	}
	upstream, err := e.dial(r.Context(), "tcp", net.JoinHostPort(host, port))
	if err != nil {
		http.Error(w, "hostsandbox: could not reach "+host+": "+err.Error(), http.StatusBadGateway)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(w, "hostsandbox: this connection cannot carry a tunnel", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		_ = client.Close()
		_ = upstream.Close()
		return
	}
	// Bytes the client sent after the CONNECT, already read into the
	// server's buffer, go first.
	if n := buffered.Reader.Buffered(); n > 0 {
		if _, err := io.CopyN(upstream, buffered, int64(n)); err != nil {
			_ = client.Close()
			_ = upstream.Close()
			return
		}
	}
	splice(client, upstream)
}

// splice copies each connection into the other until both directions end.
// When one side finishes sending, the other is told by closing its write
// half, so a protocol that ends with a half-close still completes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	copyHalf := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		} else {
			_ = dst.Close()
		}
		done <- struct{}{}
	}
	go copyHalf(a, b)
	go copyHalf(b, a)
	<-done
	<-done
	_ = a.Close()
	_ = b.Close()
}

// hopHeaders are the headers that describe one connection rather than the
// request, and the proxy credentials a client may send; none is passed on.
var hopHeaders = []string{
	"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection",
	"Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// dropHopHeaders removes the hop headers and every header the Connection
// header names.
func dropHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for name := range strings.SplitSeq(value, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range hopHeaders {
		header.Del(name)
	}
}
