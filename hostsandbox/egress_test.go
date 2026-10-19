// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// proxyTo starts the egress proxy for an allowlist with every destination
// dialed to target, whatever its name, so a test reaches its own server
// under any host name. It returns the proxy's address and the refusals it
// wrote.
func proxyTo(t *testing.T, domains []string, target string) (string, *bytes.Buffer) {
	t.Helper()
	notice := &bytes.Buffer{}
	e := newEgress(domains, notice, true)
	e.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	return server.Listener.Addr().String(), notice
}

// throughProxy is an HTTP client that sends every request through the
// proxy at address.
func throughProxy(t *testing.T, address string) *http.Client {
	t.Helper()
	proxy, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
}

// connect sends a CONNECT for target through the proxy at address and
// returns the connection and the proxy's status line.
func connect(t *testing.T, address, target string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	return conn, reader, strings.TrimSpace(status)
}

// echoServer is a TCP server that writes back each line it reads.
func echoServer(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return listener.Addr().String()
}

// TestEgressTunnelsAnAllowedHost checks that a CONNECT to a host on the
// allowlist, exact or under a wildcard, is answered 200 and carries bytes
// both ways untouched, which is what a client's own TLS needs.
func TestEgressTunnelsAnAllowedHost(t *testing.T) {
	address, notice := proxyTo(t, []string{"Example.COM", "*.pkg.test"}, echoServer(t))
	for _, target := range []string{"example.com:443", "EXAMPLE.com.:443", "registry.pkg.test:443"} {
		conn, reader, status := connect(t, address, target)
		if !strings.Contains(status, " 200 ") {
			t.Fatalf("CONNECT %s = %q, want 200", target, status)
		}
		if line, err := reader.ReadString('\n'); err != nil || line != "\r\n" {
			t.Fatalf("CONNECT %s: the status is not followed by an empty line: %q, %v", target, line, err)
		}
		if _, err := conn.Write([]byte("ping\n")); err != nil {
			t.Fatal(err)
		}
		if echoed, err := reader.ReadString('\n'); err != nil || echoed != "ping\n" {
			t.Fatalf("CONNECT %s: echoed %q, %v", target, echoed, err)
		}
	}
	if notice.Len() != 0 {
		t.Fatalf("an allowed tunnel was noted as refused: %q", notice.String())
	}
}

// TestEgressRefusesAHostNotAllowed checks that a CONNECT to a host the
// allowlist does not name, the apex under a wildcard among them, is
// answered 403 and noted in the stage's log.
func TestEgressRefusesAHostNotAllowed(t *testing.T) {
	address, notice := proxyTo(t, []string{"*.pkg.test"}, echoServer(t))
	for _, target := range []string{"evil.test:443", "pkg.test:443", "pkg.test.evil.test:443"} {
		_, _, status := connect(t, address, target)
		if !strings.Contains(status, " 403 ") {
			t.Fatalf("CONNECT %s = %q, want 403", target, status)
		}
	}
	if !strings.Contains(notice.String(), "refused a connection to evil.test") {
		t.Fatalf("the refusal was not noted: %q", notice.String())
	}
	_, _, status := connect(t, address, "no-port")
	if !strings.Contains(status, " 400 ") {
		t.Fatalf("a CONNECT with no port = %q, want 400", status)
	}
}

// TestEgressForwardsAPlainRequest checks that a request for an absolute http
// URL on an allowed host is forwarded without the proxy's own headers, and
// that one for another host is refused.
func TestEgressForwardsAPlainRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("X-Hop") != "" {
			http.Error(w, "a hop header was passed on", http.StatusTeapot)
			return
		}
		w.Header().Set("Connection", "X-Upstream-Hop")
		w.Header().Set("X-Upstream-Hop", "dropped")
		_, _ = fmt.Fprintf(w, "hello from %s%s", r.Host, r.URL.Path)
	}))
	t.Cleanup(upstream.Close)
	address, notice := proxyTo(t, []string{"allowed.test"}, upstream.Listener.Addr().String())
	client := throughProxy(t, "http://"+address)

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://allowed.test/path", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	request.Header.Set("Connection", "X-Hop")
	request.Header.Set("X-Hop", "drop me")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "hello from allowed.test/path" {
		t.Fatalf("an allowed request = %d %q", response.StatusCode, body)
	}
	if response.Header.Get("X-Upstream-Hop") != "" {
		t.Fatal("a header the upstream's Connection named was passed back")
	}

	denied, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://denied.test/", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err = client.Do(denied)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !strings.Contains(notice.String(), "denied.test") {
		t.Fatalf("a request for another host = %d, notice %q", response.StatusCode, notice.String())
	}
}

// TestEgressRefusesARequestThatIsNotForAProxy checks that a request in
// origin form, as for a web server, is refused.
func TestEgressRefusesARequestThatIsNotForAProxy(t *testing.T) {
	address, _ := proxyTo(t, []string{"allowed.test"}, echoServer(t))
	response, err := http.Get("http://" + address + "/") //nolint:noctx // a test of the proxy's refusal
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("an origin-form request = %d, want 400", response.StatusCode)
	}
}

// TestEgressReportsAnUnreachableHost checks that an allowed host that cannot
// be reached is answered 502, for a tunnel and for a plain request.
func TestEgressReportsAnUnreachableHost(t *testing.T) {
	e := newEgress([]string{"allowed.test"}, io.Discard, true)
	e.dial = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("no route") }
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	_, _, status := connect(t, server.Listener.Addr().String(), "allowed.test:443")
	if !strings.Contains(status, " 502 ") {
		t.Fatalf("CONNECT to an unreachable host = %q, want 502", status)
	}
	client := throughProxy(t, server.URL)
	response, err := client.Get("http://allowed.test/") //nolint:noctx // a test of the proxy's answer
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("a plain request to an unreachable host = %d, want 502", response.StatusCode)
	}
}

// TestEgressRefusesThisMachine checks that a destination on this machine or
// its link-local network is refused on the address it resolves to, even
// when its name is allowed: a stage must not reach a service the host runs,
// or a cloud's metadata endpoint, through a name pointed at it.
func TestEgressRefusesThisMachine(t *testing.T) {
	for _, address := range []string{"127.0.0.1:80", "[::1]:443", "0.0.0.0:80", "169.254.169.254:80", "[fe80::1]:80", "not-an-address"} {
		if err := refuseLocal("tcp", address, nil); err == nil {
			t.Errorf("refuseLocal(%q) admitted it", address)
		}
	}
	if err := refuseLocal("tcp", "93.184.215.14:443", nil); err != nil {
		t.Errorf("refuseLocal refused a public address: %v", err)
	}
	upstream := echoServer(t)
	_, port, _ := net.SplitHostPort(upstream)
	e := newEgress([]string{"localhost", "127.0.0.1"}, io.Discard, false)
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	for _, host := range []string{"localhost", "127.0.0.1"} {
		_, _, status := connect(t, server.Listener.Addr().String(), net.JoinHostPort(host, port))
		if !strings.Contains(status, " 502 ") {
			t.Fatalf("CONNECT %s:%s = %q, want it refused", host, port, status)
		}
	}
}

// TestSpliceEndsWhenBothSidesHaveFinished checks that a tunnel whose client
// closes its sending half still delivers the server's answer, and that the
// tunnel closes once both sides are done.
func TestSpliceEndsWhenBothSidesHaveFinished(t *testing.T) {
	clientEnd, proxyClient := net.Pipe()
	proxyUpstream, upstreamEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		splice(proxyClient, proxyUpstream)
		close(done)
	}()
	go func() {
		buffer := make([]byte, 4)
		_, _ = io.ReadFull(upstreamEnd, buffer)
		_, _ = upstreamEnd.Write([]byte("pong"))
		_ = upstreamEnd.Close()
	}()
	if _, err := clientEnd.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	answer := make([]byte, 4)
	if _, err := io.ReadFull(clientEnd, answer); err != nil || string(answer) != "pong" {
		t.Fatalf("answer = %q, %v", answer, err)
	}
	_ = clientEnd.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the tunnel did not end after both sides finished")
	}
}
