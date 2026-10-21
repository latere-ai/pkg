// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// The allowlist's decisions, pinned. A change to any row below changes what
// a stage with an allowlist may reach.

// pinnedAllowlist is the allowlist every pinned decision is made against.
var pinnedAllowlist = []string{
	"Exact.TEST", "trailing.test.", "  spaced.test  ", "*.wild.test", "ssh.test:22", "*.ports.test:8443",
	"alt.test:0080", "bad.test:99999", "zero.test:0", "worse.test:abc", "2001:db8::1", "[2001:db8::2]:8443",
	"192.0.2.10", "",
}

// answer sends a CONNECT for target through the proxy at address and
// returns the proxy's answer: its status line and its body, read by its
// length, since the proxy keeps the connection open after a refusal.
func answer(t *testing.T, address, target string) (string, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode/100 == 2 {
		// An established tunnel has no body.
		return response.Proto + " " + response.Status, ""
	}
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response.Proto + " " + response.Status, string(body)
}

// TestAllowlistDecisionsArePinned checks admits, the allowlist's decision, for
// every way an entry and a request can be spelled.
func TestAllowlistDecisionsArePinned(t *testing.T) {
	e := newEgress(pinnedAllowlist, io.Discard, true)
	for _, c := range []struct {
		host, port string
		tunnel     bool
		want       bool
	}{
		// A host named alone: a CONNECT to 443, a plain request to 80, in any
		// case and with or without a trailing dot, and nothing else.
		{"exact.test", "443", true, true},
		{"EXACT.test.", "443", true, true},
		{" exact.test ", "443", true, true},
		{"exact.test", "80", false, true},
		{"exact.test", "80", true, false},
		{"exact.test", "443", false, false},
		{"exact.test", "22", true, false},
		{"exact.test", "8443", true, false},
		{"sub.exact.test", "443", true, false},
		{"trailing.test", "443", true, true},
		{"spaced.test", "443", true, true},
		// A port is read as a number from 1 to 65535.
		{"exact.test", "0443", true, true},
		{"exact.test", "00080", false, true},
		{"exact.test", "not-a-port", true, false},
		{"exact.test", "", true, false},
		{"exact.test", "0", true, false},
		{"exact.test", "65536", true, false},
		{"exact.test", "-443", true, false},
		{"exact.test", "+443", true, true},
		// A wildcard covers every name below it, never its apex or a name
		// that only ends the same way.
		{"a.wild.test", "443", true, true},
		{"deep.a.wild.test", "443", true, true},
		{"wild.test", "443", true, false},
		{"evil-wild.test", "443", true, false},
		{"a.wild.test.evil.test", "443", true, false},
		// host:port admits that port alone, for either kind of request.
		{"ssh.test", "22", true, true},
		{"ssh.test", "22", false, true},
		{"ssh.test", "443", true, false},
		{"ssh.test", "80", false, false},
		{"a.ports.test", "8443", true, true},
		{"ports.test", "8443", true, false},
		{"a.ports.test", "443", true, false},
		{"alt.test", "80", false, true},
		{"alt.test", "80", true, true},
		{"alt.test", "443", true, false},
		// A malformed port admits nothing, on any port.
		{"bad.test", "99999", true, false},
		{"bad.test", "443", true, false},
		{"zero.test", "443", true, false},
		{"worse.test", "443", true, false},
		{"worse.test", "abc", true, false},
		// Addresses are names like any other.
		{"2001:db8::1", "443", true, true},
		{"2001:DB8::1", "443", true, true},
		{"2001:db8:0::1", "443", true, false},
		{"2001:db8::2", "8443", true, true},
		{"192.0.2.10", "80", false, true},
		{"192.0.2.11", "80", false, false},
		// Nothing is admitted for no host.
		{"", "443", true, false},
		{"other.test", "443", true, false},
	} {
		if got := e.admits(c.host, c.port, c.tunnel); got != c.want {
			t.Errorf("admits(%q, %q, tunnel %v) = %v, want %v", c.host, c.port, c.tunnel, got, c.want)
		}
	}
}

// TestAllowlistDialCheckIsPinned checks refuseLocal, the allowlist's check of
// the address a name resolved to: it refuses this machine and its
// link-local network, and admits every other address, private ones among
// them, since a host on the allowlist was named by the person.
func TestAllowlistDialCheckIsPinned(t *testing.T) {
	refused := []string{
		"127.0.0.1:443", "127.255.255.254:443", "[::1]:443", "0.0.0.0:443", "[::]:443",
		"169.254.169.254:80", "169.254.0.1:443", "[fe80::1]:443", "[fe80::1%en0]:443",
		"224.0.0.251:443", "[ff02::1]:443", "[::ffff:127.0.0.1]:443", "[::ffff:169.254.169.254]:80",
		"not-an-address", "name.test:443", ":443",
	}
	for _, address := range refused {
		if err := refuseLocal("tcp", address, nil); err == nil {
			t.Errorf("refuseLocal(%q) admitted it", address)
		}
	}
	admitted := []string{
		"93.184.215.14:443", "[2606:4700::1]:443", "10.0.0.1:443", "172.16.0.1:443", "192.168.1.1:443",
		"100.64.0.1:443", "[fc00::1]:443", "[fd7a:115c:a1e0::1]:443", "239.1.1.1:443", "0.0.0.1:443",
		"[::127.0.0.1]:443", "[64:ff9b::7f00:1]:443", "255.255.255.255:443",
	}
	for _, address := range admitted {
		if err := refuseLocal("tcp", address, nil); err != nil {
			t.Errorf("refuseLocal(%q) refused it: %v", address, err)
		}
	}
}

// TestAllowlistAnswersArePinned checks what the proxy answers and what it
// writes to the stage's log, for a refusal and for a request it cannot read.
func TestAllowlistAnswersArePinned(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(upstream.Close)
	address, notice := proxyTo(t, pinnedAllowlist, upstream.Listener.Addr().String())
	status, body := answer(t, address, "other.test:443")
	if status != "HTTP/1.1 403 Forbidden" {
		t.Fatalf("a refused CONNECT = %q", status)
	}
	if body != "hostsandbox: other.test:443 is not on this stage's network allowlist\n" {
		t.Fatalf("a refused CONNECT's body = %q", body)
	}
	const line = "hostsandbox: refused a connection to other.test:443, which is not on this stage's network allowlist\n"
	if notice.String() != line {
		t.Fatalf("the refusal's line = %q, want %q", notice.String(), line)
	}
	notice.Reset()
	_, _, status = connect(t, address, "[2001:DB8::3]:443")
	if status != "HTTP/1.1 403 Forbidden" || notice.String() != "hostsandbox: refused a connection to [2001:DB8::3]:443, which is not on this stage's network allowlist\n" {
		t.Fatalf("a refused address = %q, line %q", status, notice.String())
	}
	client := throughProxy(t, "http://"+address)
	for url, want := range map[string]int{
		"http://exact.test/": http.StatusOK, "http://exact.test:80/": http.StatusOK, "http://EXACT.test./": http.StatusOK,
		"http://other.test/": http.StatusForbidden, "http://exact.test:443/": http.StatusForbidden,
		"http://ssh.test:22/": http.StatusOK, "http://alt.test/": http.StatusOK,
	} {
		response, err := client.Get(url) //nolint:noctx // a test of the proxy's answer
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != want {
			t.Errorf("GET %s = %d, want %d", url, response.StatusCode, want)
		}
	}
	for target, want := range map[string]string{"no-port": "HTTP/1.1 400 Bad Request", "exact.test:": "HTTP/1.1 403 Forbidden"} {
		if _, _, status := connect(t, address, target); status != want {
			t.Errorf("CONNECT %s = %q, want %q", target, status, want)
		}
	}
}
