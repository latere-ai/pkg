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
	"net/netip"
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
//
// For a deny list, the proxy admits any host that is a well-formed name or
// address on the standard ports, and the hosts Domains names with a port on
// that port, unless the deny list blocks it; a blocked host is refused
// before its name is looked up. Every destination is then checked on the
// address it resolves to by refuseNonPublic, which refuses far more than
// refuseLocal does, and against the addresses the deny list names.
type egress struct {
	// standard admits the hosts named without a port, on the standard
	// ports; byPort admits the hosts named with a port, on that port.
	standard hostmatch.Matcher
	byPort   map[string]hostmatch.Matcher
	// anyHost admits every well-formed host on the standard ports: a deny
	// list. blocked refuses the hosts it names alone on every port, and
	// blockedByPort those named with a port on that port, an address among
	// them in its canonical form. blockedAddrs and blockedAddrPorts are the
	// addresses among them, which the dialer refuses whatever name reached
	// them.
	anyHost          bool
	blocked          hostmatch.Matcher
	blockedByPort    map[string]hostmatch.Matcher
	blockedAddrs     map[netip.Addr]bool
	blockedAddrPorts map[netip.AddrPort]bool
	// dial reaches a destination; forward carries a plain request.
	dial    func(ctx context.Context, network, address string) (net.Conn, error)
	forward http.RoundTripper
	// notice receives one line for each refusal. The launcher passes the
	// stage's own log, so whoever reads the stage's output sees why a
	// connection failed.
	notice io.Writer
}

// egressFor builds the proxy for a stage's network: an allowlist, as
// newEgress does, or a deny list. It refuses any other mode, a deny list on
// an allowlist, and a deny-list entry it cannot read, since an entry that
// blocks nothing is a hole the person does not know of.
func egressFor(network Network, notice io.Writer, localOK bool) (*egress, error) {
	if err := checkNetwork(network); err != nil {
		return nil, err
	}
	switch network.Mode {
	case NetworkAllowlist:
		return newEgress(network.Domains, notice, localOK), nil
	case NetworkDenylist:
		var e *egress
		// The dialer always checks the deny list's addresses; only this
		// package's tests skip the check of what is not public.
		control := func(network, address string, conn syscall.RawConn) error {
			if !localOK {
				if err := refuseNonPublic(network, address, conn); err != nil {
					return err
				}
			}
			return e.refuseBlockedAddress(address)
		}
		e = buildEgress(network.Domains, notice, control)
		e.anyHost = true
		e.blockedAddrs, e.blockedAddrPorts = map[netip.Addr]bool{}, map[netip.AddrPort]bool{}
		blocked := make([]string, 0, len(network.Blocked))
		for _, entry := range network.Blocked {
			blocked = append(blocked, e.blockAddress(strings.TrimSpace(entry)))
		}
		plain, byPort := splitAllowlist(blocked)
		e.blocked, e.blockedByPort = hostmatch.New(plain, normalizeHost), matchers(byPort)
		return e, nil
	}
	return nil, fmt.Errorf("%w: the egress proxy serves an allowlist or a deny list, not a %q network", ErrUnenforceableNetwork, network.Mode)
}

// checkNetwork refuses a deny list on a network that is not one, and a
// deny-list entry that does not read as a host or host:port.
func checkNetwork(network Network) error {
	if network.Mode != NetworkDenylist {
		if len(sorted(network.Blocked)) > 0 {
			return fmt.Errorf("%w: a %q network blocks nothing; a deny list is a %q network's", ErrUnenforceableNetwork, network.Mode, NetworkDenylist)
		}
		return nil
	}
	for _, entry := range network.Blocked {
		if !validBlockedEntry(strings.TrimSpace(entry)) {
			return fmt.Errorf("%w: the deny-list entry %q is not a host, an address or a wildcard over a host, alone or with a port from 1 to 65535", ErrUnenforceableNetwork, entry)
		}
	}
	return nil
}

// validBlockedEntry reports whether a deny-list entry reads as a host, an
// address or a "*." wildcard over a host, alone or with a port.
func validBlockedEntry(entry string) bool {
	if entry == "" {
		return true
	}
	host := entry
	if h, port, err := net.SplitHostPort(entry); err == nil {
		if _, ok := portNumber(port); !ok {
			return false
		}
		host = h
	}
	host = normalizeHost(host)
	return validHost(strings.TrimPrefix(host, "*."))
}

// blockAddress records a deny-list entry that names an address, alone or
// with a port, for the dialer to refuse, and returns the entry with the
// address in the form reachedAddress gives, so every spelling of it
// matches. Any other entry is returned as it is.
func (e *egress) blockAddress(entry string) string {
	host, port, err := net.SplitHostPort(entry)
	if err != nil {
		host, port = entry, ""
	}
	ip, ok := reachedAddress(normalizeHost(host))
	if !ok {
		return entry
	}
	if port == "" {
		e.blockedAddrs[ip] = true
		return ip.String()
	}
	canonical, _ := portNumber(port)
	number, _ := strconv.Atoi(canonical)
	e.blockedAddrPorts[netip.AddrPortFrom(ip, uint16(number))] = true //nolint:gosec // portNumber bounds it to 65535
	return net.JoinHostPort(ip.String(), canonical)
}

// refuseBlockedAddress refuses a dialed address the deny list names, alone
// or with the dialed port.
func (e *egress) refuseBlockedAddress(address string) error {
	dialed, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("check destination %q: %w", address, err)
	}
	ip := reached(dialed.Addr())
	if e.blockedAddrs[ip] || e.blockedAddrPorts[netip.AddrPortFrom(ip, dialed.Port())] {
		return fmt.Errorf("%w: %s", errBlockedDestination, ip)
	}
	return nil
}

// errBlockedDestination is an address the deny list names, reached through
// a name.
var errBlockedDestination = errors.New("the destination's address is on this stage's deny list")

// newEgress builds the proxy for an allowlist. localOK admits destinations
// on this machine, which only this package's tests do.
func newEgress(domains []string, notice io.Writer, localOK bool) *egress {
	var control func(network, address string, conn syscall.RawConn) error
	if !localOK {
		control = refuseLocal
	}
	return buildEgress(domains, notice, control)
}

// buildEgress builds the proxy that admits domains as an allowlist does,
// checking every address it dials with control, when there is one.
func buildEgress(domains []string, notice io.Writer, control func(network, address string, conn syscall.RawConn) error) *egress {
	dialer := &net.Dialer{Timeout: egressDialTimeout, KeepAlive: 30 * time.Second, Control: control}
	plain, byPort := splitAllowlist(domains)
	e := &egress{standard: hostmatch.New(plain, normalizeHost), byPort: matchers(byPort), dial: dialer.DialContext, notice: notice}
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

// matchers compiles the hosts named with each port.
func matchers(byPort map[string][]string) map[string]hostmatch.Matcher {
	out := make(map[string]hostmatch.Matcher, len(byPort))
	for port, hosts := range byPort {
		out[port] = hostmatch.New(hosts, normalizeHost)
	}
	return out
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

// admits reports whether the network admits host on port, for a CONNECT
// when tunnel is true and a plain request otherwise. For an allowlist, the
// first test is never made, so its decisions are the allowlist's alone.
func (e *egress) admits(host, port string, tunnel bool) bool {
	host = normalizeHost(host)
	port, ok := portNumber(port)
	if !ok {
		return false
	}
	if e.anyHost && (!validHost(host) || e.blocks(host, port)) {
		return false
	}
	if matcher, ok := e.byPort[port]; ok && matcher.Matches(host) {
		return true
	}
	standard := plainPort
	if tunnel {
		standard = tunnelPort
	}
	return port == standard && (e.anyHost || e.standard.Matches(host))
}

// blocks reports whether the deny list blocks a normalized host on a
// canonical port. An address is matched as the address it reaches, so no
// spelling of a blocked address gets past it.
func (e *egress) blocks(host, port string) bool {
	if ip, ok := reachedAddress(host); ok {
		host = ip.String()
	}
	if e.blocked.Matches(host) {
		return true
	}
	matcher, ok := e.blockedByPort[port]
	return ok && matcher.Matches(host)
}

// refuse answers a request for a host and port the network does not admit,
// and says so in the stage's log.
func (e *egress) refuse(w http.ResponseWriter, host, port string) {
	target := net.JoinHostPort(host, port)
	if e.anyHost {
		if e.notice != nil {
			_, _ = fmt.Fprintf(e.notice, "hostsandbox: refused a connection to %s, which this stage's network refuses\n", target)
		}
		http.Error(w, "hostsandbox: "+target+" is refused by this stage's network", http.StatusForbidden)
		return
	}
	if e.notice != nil {
		_, _ = fmt.Fprintf(e.notice, "hostsandbox: refused a connection to %s, which is not on this stage's network allowlist\n", target)
	}
	http.Error(w, "hostsandbox: "+target+" is not on this stage's network allowlist", http.StatusForbidden)
}

// unreachable answers a request whose destination could not be reached.
// Under a deny list, every failure is answered alike, without its cause: a
// destination refused for its address, one that does not resolve and one
// that does not answer read the same, so a stage learns neither what a name
// resolves to nor whether a name on a local network exists, but for how
// long the answer took. An address the deny list names is answered as a
// refusal.
func (e *egress) unreachable(w http.ResponseWriter, host string, err error) {
	if !e.anyHost {
		http.Error(w, "hostsandbox: could not reach "+host+": "+err.Error(), http.StatusBadGateway)
		return
	}
	if errors.Is(err, errBlockedDestination) {
		http.Error(w, "hostsandbox: "+host+" is refused by this stage's network", http.StatusForbidden)
		return
	}
	http.Error(w, "hostsandbox: could not reach "+host+": "+unreachableReason, http.StatusBadGateway)
}

// unreachableReason is why a deny list could not reach a host, the same for
// every failure.
const unreachableReason = "it does not resolve, does not answer, or is on this machine or a local network, which this stage's network does not reach"

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
		e.unreachable(w, host, err)
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
		e.unreachable(w, host, err)
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
