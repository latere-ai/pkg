// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// The deny list under macOS's own Seatbelt, which only darwin has.

//go:build darwin

package hostsandbox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// seatbeltHere composes a driver under the real Seatbelt, with a home
// directory of its own resolved through its links. macOS always has it.
func seatbeltHere(t *testing.T) (*Driver, string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	driver := New(Config{Isolation: IsolationSeatbelt, Home: home, Lookup: os.LookupEnv, StopGrace: 2 * time.Second})
	if err := driver.Preflight(context.Background()); err != nil {
		t.Fatalf("Seatbelt is not ready on this Mac: %v", err)
	}
	return driver, home
}

// TestSeatbeltDenylistGoesOnlyThroughTheProxy runs deny-list stages under the
// real Seatbelt, with this test binary as their launcher: a host the deny
// list does not block is reached through the proxy, a blocked one is
// refused with its line in the stage's output, and a connection around the
// proxy is refused by the sandbox.
func TestSeatbeltDenylistGoesOnlyThroughTheProxy(t *testing.T) {
	driver, home := seatbeltHere(t)
	localDestinations = true
	t.Cleanup(func() { localDestinations = false })
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "reached through the proxy") }))
	t.Cleanup(server.Close)
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	spec := func(argv ...string) StageSpec {
		return StageSpec{
			Name: "denylist", Argv: argv, Workdir: home,
			Paths:   []Path{{Host: home, Access: ReadWrite}},
			Network: Network{Mode: NetworkDenylist, Domains: []string{"localhost:" + address.Port()}, Blocked: []string{"denied.test"}},
			Env:     coverage(t),
		}
	}
	if output, err := attached(t, driver, spec("/usr/bin/curl", "-q", "-sS", "--max-time", "10", "http://localhost:"+address.Port()+"/")); err != nil || output != "reached through the proxy" {
		t.Fatalf("a host not blocked = %q, %v", output, err)
	}
	output, err := attached(t, driver, spec("/usr/bin/curl", "-q", "-sS", "--max-time", "10", "-o", "/dev/null", "-w", "%{http_code}", "http://denied.test/secret?token=abc"))
	if !strings.HasSuffix(output, "403") || !strings.Contains(output, "refused a connection to denied.test:80") {
		t.Fatalf("a blocked host = %q, %v, want 403 and the refusal named", output, err)
	}
	if output, err := attached(t, driver, spec("/usr/bin/curl", "-q", "-sS", "--max-time", "5", "--noproxy", "*", server.URL)); err == nil || strings.Contains(output, "reached") {
		t.Fatalf("a connection around the proxy succeeded: %q, %v", output, err)
	}
}

// TestSeatbeltDenylistRefusesThisMachine runs a deny-list stage under the
// real Seatbelt whose launcher checks every address, as a consumer's does:
// this machine and the cloud metadata endpoint are refused whatever the
// name, and the answer names neither address.
func TestSeatbeltDenylistRefusesThisMachine(t *testing.T) {
	driver, home := seatbeltHere(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "reached") }))
	t.Cleanup(server.Close)
	address, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"http://localhost:" + address.Port() + "/", "http://127.0.0.1:" + address.Port() + "/", "http://169.254.169.254/latest/meta-data/", "http://[::ffff:127.0.0.1]:" + address.Port() + "/"} {
		output, err := attached(t, driver, StageSpec{
			Name: "denylist", Argv: []string{"/usr/bin/curl", "-q", "-sS", "--max-time", "10", target}, Workdir: home,
			Paths:   []Path{{Host: home, Access: ReadWrite}},
			Network: Network{Mode: NetworkDenylist, Domains: []string{"localhost:" + address.Port(), "127.0.0.1:" + address.Port(), "[::ffff:127.0.0.1]:" + address.Port()}},
			Env:     coverage(t),
		})
		if err != nil || !strings.Contains(output, "is on this machine or a local network") || strings.Contains(output, "reached") {
			t.Fatalf("%s = %q, %v, want it refused", target, output, err)
		}
		if strings.Contains(output, "dial") {
			t.Fatalf("%s's refusal names the address it resolved to: %q", target, output)
		}
	}
}
