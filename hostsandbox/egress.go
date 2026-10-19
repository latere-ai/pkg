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
// the host it names: a CONNECT's target, or a plain request's absolute URL.
// It never terminates TLS and holds no certificate authority: a tunnel
// carries the client's own TLS end to end, so the proxy learns the host it
// is asked for and nothing of what passes through.
//
// A destination on this machine or its link-local network is refused even
// when its name is allowed, and is checked on the address the name resolves
// to, so a name an attacker points at 127.0.0.1 does not reach a service
// the host runs.
type egress struct {
	allowed hostmatch.Matcher
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
	e := &egress{allowed: hostmatch.New(domains, normalizeHost), dial: dialer.DialContext, notice: notice}
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

func (e *egress) admits(host string) bool { return e.allowed.Matches(normalizeHost(host)) }

// refuse answers a request for a host the allowlist does not name, and says
// so in the stage's log.
func (e *egress) refuse(w http.ResponseWriter, host string) {
	if e.notice != nil {
		_, _ = fmt.Fprintf(e.notice, "hostsandbox: refused a connection to %s, which is not on this stage's network allowlist\n", host)
	}
	http.Error(w, "hostsandbox: "+host+" is not on this stage's network allowlist", http.StatusForbidden)
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
	host := r.URL.Hostname()
	if !e.admits(host) {
		e.refuse(w, host)
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
	if !e.admits(host) {
		e.refuse(w, host)
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
