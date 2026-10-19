// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An allowed host must not be a tunnel to another port of it.

// TestEgressAdmitsOnlyTheStandardPortsUnlessNamed checks that a host named
// alone is reached by a CONNECT to 443 and a plain request to 80 and on no
// other port, that host:port admits that port alone, that a malformed port
// admits nothing, and that a refused port is noted with the host.
func TestEgressAdmitsOnlyTheStandardPortsUnlessNamed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") }))
	t.Cleanup(upstream.Close)
	address, notice := proxyTo(t, []string{"web.test", "ssh.test:22", "alt.test:8080", "bad.test:99999", "worse.test:abc", "2001:db8::1"}, upstream.Listener.Addr().String())
	for target, want := range map[string]string{
		"web.test:443": " 200 ", "web.test:22": " 403 ", "web.test:5432": " 403 ", "web.test:80": " 403 ",
		"ssh.test:22": " 200 ", "ssh.test:443": " 403 ", "bad.test:99999": " 403 ", "bad.test:443": " 403 ",
		"worse.test:443": " 403 ", "[2001:db8::1]:443": " 200 ",
	} {
		_, _, status := connect(t, address, target)
		if !strings.Contains(status, want) {
			t.Errorf("CONNECT %s = %q, want%s", target, status, want)
		}
	}
	if !strings.Contains(notice.String(), "refused a connection to web.test:22") {
		t.Errorf("a refused port was not noted with its host: %q", notice.String())
	}
	client := throughProxy(t, "http://"+address)
	for url, want := range map[string]int{
		"http://web.test/": http.StatusOK, "http://web.test:8080/": http.StatusForbidden,
		"http://alt.test:8080/": http.StatusOK, "http://alt.test/": http.StatusForbidden,
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
	if e := newEgress([]string{"web.test"}, io.Discard, true); e.admits("web.test", "0443", true) != true || e.admits("web.test", "not-a-port", true) {
		t.Error("a port is not read as a number")
	}
}
