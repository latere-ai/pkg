// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// denylist builds the egress proxy for a deny-list network that admits this
// machine, the form a test reaches its own servers through.
func denylist(t *testing.T, network Network) *egress {
	t.Helper()
	network.Mode = NetworkDenylist
	e, err := egressFor(network, io.Discard, true)
	if err != nil {
		t.Fatalf("egressFor(%+v): %v", network, err)
	}
	return e
}

// TestDenylistAdmitsAnyHostOnTheStandardPorts checks that a deny-list
// network with nothing blocked admits any well-formed host for a CONNECT to
// 443 and a plain request to 80, and nothing on another port, which are the
// allowlist's port rules for a host named alone.
func TestDenylistAdmitsAnyHostOnTheStandardPorts(t *testing.T) {
	e := denylist(t, Network{})
	for _, c := range []struct {
		host, port string
		tunnel     bool
		want       bool
	}{
		{"example.com", "443", true, true},
		{"EXAMPLE.com.", "443", true, true},
		{"a-b.c_d.example", "443", true, true},
		{"localhost", "443", true, true},
		{"203.0.114.7", "443", true, true},
		{"2001:4860::8888", "443", true, true},
		{"example.com", "80", false, true},
		{"example.com", "0443", true, true},
		{"example.com", "80", true, false},
		{"example.com", "443", false, false},
		{"example.com", "22", true, false},
		{"example.com", "8080", false, false},
		{"example.com", "0", true, false},
		{"example.com", "65536", true, false},
		{"example.com", "https", true, false},
		{"example.com", "", true, false},
	} {
		if got := e.admits(c.host, c.port, c.tunnel); got != c.want {
			t.Errorf("admits(%q, %q, tunnel %v) = %v, want %v", c.host, c.port, c.tunnel, got, c.want)
		}
	}
}

// TestDenylistRefusesAHostThatIsNotAName checks that a host that is neither
// a host name nor an address is refused, so no spelling a resolver might
// read differently from the deny list, a doubled trailing dot or an empty
// label among them, gets past it.
func TestDenylistRefusesAHostThatIsNotAName(t *testing.T) {
	e := denylist(t, Network{Blocked: []string{"evil.test"}})
	for _, host := range []string{
		"", ".", "evil.test..", "..evil.test", "evil..test", "-evil.test", "evil-.test", "*.evil.test", "*",
		"evil.test/x", "evil test", "évil.test", "evil.test\x00", "evil%2etest", "fe80::1%en0", "[::1]",
		"user@evil.test", strings.Repeat("a", 64) + ".test", strings.Repeat("abcdefghi.", 26) + "test",
		// A name whose last label is a number, which a resolver reads as an
		// address.
		"2130706433", "0x7f000001", "0x7f.0.0.1", "127.0.0.01", "127.1", "1.1.257", "01.01.01.01", "a.0x", "a.0x7f", "evil.test.1",
	} {
		if e.admits(host, "443", true) {
			t.Errorf("admits(%q) for a host that is not a name", host)
		}
	}
	for _, host := range []string{strings.Repeat("a", 63) + ".test", "123.example", "1.2.3.example", "a.0xg", "xn--vil-bma.test"} {
		if !e.admits(host, "443", true) {
			t.Errorf("admits(%q) refused a name", host)
		}
	}
}

// TestDenylistRefusesWhatItBlocks checks the deny list: an entry matches as
// an allowlist entry does, exact or under a wildcard and in any spelling of
// the name; a host named alone is blocked on every port and host:port on
// that port alone; and a blocked host stays blocked when Domains names it.
func TestDenylistRefusesWhatItBlocks(t *testing.T) {
	e := denylist(t, Network{
		Blocked: []string{"Evil.TEST.", "*.bad.test", "ssh.test:22", "198.51.100.9", "2001:db8::66", "[2001:db8::67]:443", " spaced.test "},
		Domains: []string{"evil.test:8443", "ssh.test:22", "ok.test:22", "a.bad.test"},
	})
	for _, c := range []struct {
		host, port string
		tunnel     bool
		want       bool
	}{
		{"evil.test", "443", true, false},
		{"EVIL.test.", "443", true, false},
		{" evil.test ", "80", false, false},
		{"evil.test", "8443", true, false},
		{"sub.evil.test", "443", true, true},
		{"a.bad.test", "443", true, false},
		{"deep.a.bad.test", "80", false, false},
		{"bad.test", "443", true, true},
		{"notbad.test", "443", true, true},
		{"spaced.test", "443", true, false},
		{"ssh.test", "22", true, false},
		{"ssh.test", "443", true, true},
		{"ok.test", "22", true, true},
		{"other.test", "22", true, false},
		{"198.51.100.9", "443", true, false},
		{"2001:db8::66", "443", true, false},
		{"2001:db8::67", "443", true, false},
		{"2001:db8::67", "80", false, true},
	} {
		if got := e.admits(c.host, c.port, c.tunnel); got != c.want {
			t.Errorf("admits(%q, %q, tunnel %v) = %v, want %v", c.host, c.port, c.tunnel, got, c.want)
		}
	}
}

// TestDenylistAdmitsWhatTheAllowlistAdmits checks that a deny-list network
// whose Domains are the pinned allowlist admits every host and port the
// allowlist does, on the same port rules: the mode only widens the
// allowlist, by any host on the standard ports.
func TestDenylistAdmitsWhatTheAllowlistAdmits(t *testing.T) {
	allow := newEgress(pinnedAllowlist, io.Discard, true)
	deny := denylist(t, Network{Domains: pinnedAllowlist})
	for _, host := range []string{"exact.test", "a.wild.test", "ssh.test", "a.ports.test", "alt.test", "bad.test", "2001:db8::2", "other.test"} {
		for _, port := range []string{"22", "80", "443", "8443", "99999"} {
			for _, tunnel := range []bool{true, false} {
				if allow.admits(host, port, tunnel) && !deny.admits(host, port, tunnel) {
					t.Errorf("the allowlist admits %s:%s (tunnel %v) and the deny list does not", host, port, tunnel)
				}
				standard := port == "443" && tunnel || port == "80" && !tunnel
				if !allow.admits(host, port, tunnel) && deny.admits(host, port, tunnel) && !standard {
					t.Errorf("the deny list admits %s:%s (tunnel %v), off the standard ports, which the allowlist does not", host, port, tunnel)
				}
			}
		}
	}
}

// TestEgressForRefusesWhatItCannotEnforce checks that the proxy is built only
// for an allowlist or a deny list, and refuses a deny-list entry it cannot
// read rather than blocking nothing with it.
func TestEgressForRefusesWhatItCannotEnforce(t *testing.T) {
	for _, network := range []Network{
		{Mode: NetworkNone}, {Mode: NetworkOpen}, {Mode: ""},
		{Mode: NetworkDenylist, Blocked: []string{"evil.test:99999"}},
		{Mode: NetworkDenylist, Blocked: []string{"evil.test:abc"}},
		{Mode: NetworkDenylist, Blocked: []string{"*"}},
		{Mode: NetworkDenylist, Blocked: []string{"evil test"}},
		{Mode: NetworkAllowlist, Domains: []string{"example.com"}, Blocked: []string{"evil.test"}},
	} {
		if _, err := egressFor(network, io.Discard, true); !errors.Is(err, ErrUnenforceableNetwork) {
			t.Errorf("egressFor(%+v) = %v, want ErrUnenforceableNetwork", network, err)
		}
	}
	allow, err := egressFor(Network{Mode: NetworkAllowlist, Domains: pinnedAllowlist}, io.Discard, true)
	if err != nil {
		t.Fatal(err)
	}
	pinned := newEgress(pinnedAllowlist, io.Discard, true)
	for _, host := range []string{"exact.test", "a.wild.test", "ssh.test", "other.test", "2001:db8::2"} {
		for _, port := range []string{"22", "80", "443", "8443"} {
			if allow.admits(host, port, true) != pinned.admits(host, port, true) || allow.admits(host, port, false) != pinned.admits(host, port, false) {
				t.Errorf("an allowlist built through egressFor decides %s:%s differently", host, port)
			}
		}
	}
}

// nonPublic is every kind of address the deny list refuses whatever the
// name, each at the edges of its range.
var nonPublic = []string{
	// This machine, and "this network".
	"127.0.0.1", "127.255.255.255", "0.0.0.0", "0.255.255.255", "::1", "::",
	// Link-local, the cloud metadata endpoint among it.
	"169.254.169.254", "169.254.0.0", "169.254.255.255", "fe80::1", "febf:ffff::1",
	// Private networks, the carrier-grade NAT range tailnets use, and
	// unique local addresses.
	"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255",
	"100.64.0.0", "100.127.255.255", "fc00::", "fd7a:115c:a1e0::1", "fdff:ffff::1",
	// Special purpose, documentation and benchmarking ranges, the last
	// where a proxy app's fake addresses are.
	"192.0.0.1", "192.0.2.1", "192.88.99.1", "198.51.100.1", "203.0.113.1", "2001:db8::1", "3fff::1", "2001::1", "2001:1ff::1",
	"198.18.0.0", "198.18.0.1", "198.19.255.255",
	// Multicast, reserved and broadcast.
	"224.0.0.1", "239.255.255.255", "240.0.0.1", "255.255.255.255", "ff02::1", "ff05::2",
	// Deprecated and reserved IPv6 space outside global unicast.
	"fec0::1", "100::1", "64:ff9b:1::a00:1", "4000::1", "e000::1",
	// IPv4 inside IPv6: mapped, compatible, NAT64 and 6to4, each carrying a
	// refused address.
	"::ffff:127.0.0.1", "::ffff:169.254.169.254", "::ffff:10.0.0.1", "::ffff:100.64.0.1", "::ffff:0.0.0.0",
	"::127.0.0.1", "::10.0.0.1", "::8.8.8.8", "::ffff:0:7f00:1",
	"64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe", "64:ff9b::c0a8:101",
	"2002:7f00:1::1", "2002:a9fe:a9fe::1", "2002:c0a8:101::1",
}

// public is addresses the deny list admits, those just outside a refused
// range among them.
var public = []string{
	"8.8.8.8", "1.1.1.1", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "169.253.255.255",
	"169.255.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0", "223.255.255.255",
	"2001:4860:4860::8888", "2606:4700:4700::1111", "2a00:1450::1", "2001:200::1", "3fff:1000::1", "3ffe::1",
	"::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
}

// TestDenylistRefusesWhatIsNotPublic checks refuseNonPublic, the deny
// list's check of the address a name resolved to.
func TestDenylistRefusesWhatIsNotPublic(t *testing.T) {
	noNetworks(t)
	for _, ip := range nonPublic {
		address := net.JoinHostPort(ip, "443")
		if err := refuseNonPublic("tcp", address, nil); !errors.Is(err, errNonPublicDestination) {
			t.Errorf("refuseNonPublic(%q) = %v, want it refused", address, err)
		}
	}
	for _, address := range []string{"[fe80::1%en0]:443", "[2001:4860::8888%en0]:443", "not-an-address", "name.test:443", ":443"} {
		if err := refuseNonPublic("tcp", address, nil); err == nil {
			t.Errorf("refuseNonPublic(%q) admitted it", address)
		}
	}
	for _, ip := range public {
		address := net.JoinHostPort(ip, "443")
		if err := refuseNonPublic("tcp", address, nil); err != nil {
			t.Errorf("refuseNonPublic(%q) = %v, want it admitted", address, err)
		}
	}
}

// noNetworks makes this machine's own networks none, so a check of an
// address depends on the address alone.
func noNetworks(tb testing.TB) {
	tb.Helper()
	withNetworks(tb, nil, nil)
}

// withNetworks makes this machine one broadcast interface on each of the
// networks given, or makes listing its interfaces fail with err.
func withNetworks(tb testing.TB, networks []netip.Prefix, err error) {
	tb.Helper()
	saved := interfaces
	interfaces = func() ([]localInterface, error) {
		if err != nil {
			return nil, err
		}
		item := localInterface{flags: net.FlagUp | net.FlagBroadcast}
		for _, network := range networks {
			item.addrs = append(item.addrs, &net.IPNet{IP: network.Addr().AsSlice(), Mask: net.CIDRMask(network.Bits(), network.Addr().BitLen())})
		}
		return []localInterface{item}, nil
	}
	tb.Cleanup(func() { interfaces = saved })
}

// TestDenylistRefusesThisMachinesOwnNetworks checks that an address on a
// network this machine is on, or one of its own addresses, is refused even
// when it is public: a home network's devices hold global IPv6 addresses
// under the same prefix as this machine, its other networks under the same
// /48, and a service this machine runs on all interfaces answers on its own
// public address.
func TestDenylistRefusesThisMachinesOwnNetworks(t *testing.T) {
	withNetworks(t, []netip.Prefix{netip.MustParsePrefix("2a02:8070:aa::/64"), netip.MustParsePrefix("81.2.69.0/24"), netip.MustParsePrefix("149.112.112.9/32")}, nil)
	for _, ip := range []string{"2a02:8070:aa::1", "2a02:8070:aa:0:ffff::1", "2a02:8070:aa:5::1", "2a02:8070:aa:ff00::1", "81.2.69.200", "149.112.112.9", "::ffff:81.2.69.1", "64:ff9b::81.2.69.1", "64:ff9b::149.112.112.9"} {
		if err := refuseNonPublic("tcp", net.JoinHostPort(ip, "443"), nil); !errors.Is(err, errNonPublicDestination) {
			t.Errorf("an address on this machine's network, %s, = %v", ip, err)
		}
	}
	for _, ip := range []string{"2a02:8070:ab::1", "2a02:8071::1", "81.2.70.1", "149.112.112.10"} {
		if err := refuseNonPublic("tcp", net.JoinHostPort(ip, "443"), nil); err != nil {
			t.Errorf("an address off this machine's networks, %s, = %v", ip, err)
		}
	}
	withNetworks(t, nil, errors.New("no interfaces"))
	if err := refuseNonPublic("tcp", "8.8.8.8:443", nil); err == nil {
		t.Error("an address was admitted when this machine's networks could not be read")
	}
}

// TestLocalNetworksReadsThisMachine checks the networks read from this
// machine's interfaces: a broadcast interface's whole network, for a global
// IPv6 address the /48 holding it, a point-to-point interface's own address
// alone, and an implausibly wide network as its address alone.
func TestLocalNetworksReadsThisMachine(t *testing.T) {
	saved := interfaces
	t.Cleanup(func() { interfaces = saved })
	interfaces = func() ([]localInterface, error) {
		return []localInterface{
			{flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("192.168.1.20"), Mask: net.CIDRMask(24, 32)},
				&net.IPNet{IP: net.ParseIP("2a02:8070:aa::20"), Mask: net.CIDRMask(64, 128)},
				&net.IPAddr{IP: net.ParseIP("81.2.69.9")},
			}},
			{flags: net.FlagUp | net.FlagPointToPoint, addrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("198.18.0.1"), Mask: net.CIDRMask(15, 32)},
			}},
			{flags: net.FlagUp | net.FlagBroadcast, addrs: []net.Addr{
				&net.IPNet{IP: net.ParseIP("44.0.0.1"), Mask: net.CIDRMask(4, 32)},
				&net.IPNet{IP: net.ParseIP("2a03::1"), Mask: net.CIDRMask(16, 128)},
			}},
		}, nil
	}
	networks, err := localNetworks()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, network := range networks {
		got[network.String()] = true
	}
	for _, want := range []string{"192.168.1.0/24", "2a02:8070:aa::/48", "81.2.69.9/32", "198.18.0.1/32", "44.0.0.1/32", "2a03::1/128"} {
		if !got[want] {
			t.Errorf("the networks %v lack %s", networks, want)
		}
	}
	if len(networks) != 6 {
		t.Errorf("the networks = %v, want six", networks)
	}
	interfaces = func() ([]localInterface, error) { return nil, errors.New("no interfaces") }
	if _, err := localNetworks(); err == nil {
		t.Error("a failure to list the interfaces was not reported")
	}
	interfaces = saved
	if _, err := localNetworks(); err != nil {
		t.Errorf("this machine's networks: %v", err)
	}
}

// TestDenylistNeverDialsALocalAddress runs a deny-list proxy that checks
// what it dials, the form a stage gets, and checks that a name resolving to
// this machine is refused whatever it is called, and that the refusal names
// neither the address nor the network behind the name.
func TestDenylistNeverDialsALocalAddress(t *testing.T) {
	noNetworks(t)
	upstream := echoServer(t)
	_, port, _ := net.SplitHostPort(upstream)
	e, err := egressFor(Network{Mode: NetworkDenylist, Domains: []string{"localhost:" + port, "127.0.0.1:" + port}}, io.Discard, false)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	for _, host := range []string{"localhost", "127.0.0.1"} {
		status, body := answer(t, server.Listener.Addr().String(), net.JoinHostPort(host, port))
		if !strings.Contains(status, " 502 ") {
			t.Fatalf("CONNECT %s:%s = %q, want it refused", host, port, status)
		}
		if body != "hostsandbox: could not reach "+host+": "+unreachableReason+"\n" {
			t.Errorf("the refusal of %s = %q", host, body)
		}
	}
}

// fakeDNS answers every A query with the next address of a sequence, and
// every other query with no answer, over the stream framing a resolver uses
// for a connection that is not a packet connection.
type fakeDNS struct {
	mu        sync.Mutex
	addresses []netip.Addr
	asked     int
}

func (f *fakeDNS) dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go f.serve(server)
	return client, nil
}

func (f *fakeDNS) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	for {
		var size uint16
		if err := binary.Read(conn, binary.BigEndian, &size); err != nil {
			return
		}
		query := make([]byte, size)
		if _, err := io.ReadFull(conn, query); err != nil || len(query) < 12 {
			return
		}
		// The question ends four bytes after the name's terminating zero.
		end := 12
		for end < len(query) && query[end] != 0 {
			end += int(query[end]) + 1
		}
		end += 5
		if end > len(query) {
			return
		}
		qtype := binary.BigEndian.Uint16(query[end-4:])
		var answer []byte
		if qtype == 1 {
			f.mu.Lock()
			ip := f.addresses[min(f.asked, len(f.addresses)-1)]
			f.asked++
			f.mu.Unlock()
			answer = append([]byte{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4}, ip.AsSlice()...)
		}
		response := append([]byte{}, query[:2]...)
		response = append(response, 0x81, 0x80, 0, 1, 0, byte(len(answer)/16), 0, 0, 0, 0)
		response = append(response, query[12:end]...)
		response = append(response, answer...)
		if binary.Write(conn, binary.BigEndian, uint16(len(response))) != nil {
			return
		}
		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

// TestDenylistChecksEveryConnectionAtDialTime checks that the address a name
// resolves to is checked on each connection, at the moment it is dialed: a
// name that answers with a public address and then, on the next lookup,
// with this machine's is refused on the second connection, so rebinding a
// name the deny list admits reaches nothing local.
func TestDenylistChecksEveryConnectionAtDialTime(t *testing.T) {
	noNetworks(t)
	dns := &fakeDNS{addresses: []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1"), netip.MustParseAddr("169.254.169.254")}}
	var mu sync.Mutex
	var dialed []string
	errStop := errors.New("checked and admitted; the test dials nothing real")
	dialer := &net.Dialer{
		Resolver: &net.Resolver{PreferGo: true, Dial: dns.dial},
		Control: func(network, address string, conn syscall.RawConn) error {
			mu.Lock()
			dialed = append(dialed, address)
			mu.Unlock()
			if err := refuseNonPublic(network, address, conn); err != nil {
				return err
			}
			return errStop
		},
	}
	e := denylist(t, Network{})
	e.dial = dialer.DialContext
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	for _, want := range []string{"8.8.8.8:443", "127.0.0.1:443", "169.254.169.254:443"} {
		// Every failure is answered alike, so the answer does not say which
		// of these the name resolved to.
		status, body := answer(t, server.Listener.Addr().String(), "rebind.test:443")
		if status != "HTTP/1.1 502 Bad Gateway" || body != "hostsandbox: could not reach rebind.test: "+unreachableReason+"\n" {
			t.Errorf("CONNECT rebind.test resolving to %s answered %q %q", want, status, body)
		}
		mu.Lock()
		last := dialed[len(dialed)-1]
		mu.Unlock()
		if last != want {
			t.Errorf("the check saw %s, want %s", last, want)
		}
	}
}

// TestDenylistBlocksEverySpellingOfAnAddress checks that an address on the
// deny list is refused in any spelling a stage writes it in, and when a name
// resolves to it, on every port or on the one it names.
func TestDenylistBlocksEverySpellingOfAnAddress(t *testing.T) {
	e := denylist(t, Network{Blocked: []string{"1.1.1.1", "2606:4700:4700::1111", "::ffff:9.9.9.9", "8.8.8.8:53", "[2001:4860:4860:0::8888]:53"}})
	for _, c := range []struct {
		host, port string
		want       bool
	}{
		{"1.1.1.1", "443", false},
		{"::ffff:1.1.1.1", "443", false},
		{"::ffff:101:101", "443", false},
		{"2606:4700:4700::1111", "443", false},
		{"2606:4700:4700:0::1111", "443", false},
		{"2606:4700:4700:0:0:0:0:1111", "443", false},
		{"2606:4700:4700::1:1111", "443", true},
		{"9.9.9.9", "443", false},
		{"8.8.8.8", "53", false},
		{"::ffff:8.8.8.8", "53", false},
		{"2001:4860:4860::8888", "53", false},
		{"1.1.1.2", "443", true},
	} {
		if got := e.admits(c.host, c.port, true); got != c.want {
			t.Errorf("admits(%q, %q) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
	for _, address := range []string{"1.1.1.1:443", "1.1.1.1:22", "9.9.9.9:443", "[2606:4700:4700::1111]:443", "8.8.8.8:53", "[2001:4860:4860::8888]:53"} {
		if err := e.refuseBlockedAddress(address); !errors.Is(err, errBlockedDestination) {
			t.Errorf("refuseBlockedAddress(%q) = %v", address, err)
		}
		// The dialer the proxy dials with refuses it before connecting.
		if _, err := e.dial(context.Background(), "tcp", address); !errors.Is(err, errBlockedDestination) {
			t.Errorf("dialing %s = %v, want it refused", address, err)
		}
	}
	for _, address := range []string{"8.8.8.8:443", "1.1.1.2:443", "[2001:4860:4860::8888]:443"} {
		if err := e.refuseBlockedAddress(address); err != nil {
			t.Errorf("refuseBlockedAddress(%q) = %v", address, err)
		}
	}
	if err := e.refuseBlockedAddress("not-an-address"); err == nil {
		t.Error("an address that does not parse was admitted")
	}
}

// TestDenylistBlocksAnAddressHoweverItsEntryIsWritten checks that an address
// entry written with a trailing dot, in a spelling that is not canonical or
// in its NAT64 form blocks the address it names, by name and when dialed,
// and that the NAT64 form of a blocked address is blocked too.
func TestDenylistBlocksAnAddressHoweverItsEntryIsWritten(t *testing.T) {
	e := denylist(t, Network{Blocked: []string{"1.1.1.1.", "2606:4700:4700:0::1111.", "1.0.0.1.:443", "64:ff9b::808:808", "[64:ff9b::909:909]:443"}})
	for _, host := range []string{"1.1.1.1", "::ffff:1.1.1.1", "64:ff9b::101:101", "64:ff9b::1.1.1.1", "2606:4700:4700::1111", "8.8.8.8", "64:ff9b::808:808", "9.9.9.9"} {
		if e.admits(host, "443", true) {
			t.Errorf("admits(%q) for a blocked address", host)
		}
	}
	for _, address := range []string{"1.1.1.1:22", "[64:ff9b::101:101]:443", "[2606:4700:4700::1111]:443", "1.0.0.1:443", "[64:ff9b::100:1]:443", "8.8.8.8:443", "9.9.9.9:443", "[64:ff9b::909:909]:443"} {
		if err := e.refuseBlockedAddress(address); !errors.Is(err, errBlockedDestination) {
			t.Errorf("refuseBlockedAddress(%q) = %v", address, err)
		}
	}
	for _, address := range []string{"1.0.0.1:80", "9.9.9.9:80", "[64:ff9b::101:102]:443"} {
		if err := e.refuseBlockedAddress(address); err != nil {
			t.Errorf("refuseBlockedAddress(%q) = %v, want it admitted", address, err)
		}
	}
}

// TestDenylistAnswersEveryFailureAlike checks that a deny list answers a
// destination refused for its address, one that does not resolve and one
// that does not answer with the same words, and an address it names through
// a name as a refusal.
func TestDenylistAnswersEveryFailureAlike(t *testing.T) {
	e := denylist(t, Network{})
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	failures := []error{
		&net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("%w: 192.168.1.1", errNonPublicDestination)},
		&net.DNSError{Err: "no such host", Name: "printer.local", IsNotFound: true},
		&net.OpError{Op: "dial", Net: "tcp", Err: errors.New("i/o timeout")},
	}
	for _, failure := range failures {
		e.dial = func(context.Context, string, string) (net.Conn, error) { return nil, failure }
		status, body := answer(t, server.Listener.Addr().String(), "printer.local:443")
		if status != "HTTP/1.1 502 Bad Gateway" || body != "hostsandbox: could not reach printer.local: "+unreachableReason+"\n" {
			t.Errorf("a failure %v was answered %q %q", failure, status, body)
		}
	}
	e.dial = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("%w: 1.1.1.1", errBlockedDestination)}
	}
	if status, body := answer(t, server.Listener.Addr().String(), "one.test:443"); status != "HTTP/1.1 403 Forbidden" || body != "hostsandbox: one.test is refused by this stage's network\n" {
		t.Errorf("an address on the deny list was answered %q %q", status, body)
	}
	client := throughProxy(t, server.URL)
	response, err := client.Get("http://one.test/") //nolint:noctx // a test of the proxy's answer
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Errorf("a plain request to an address on the deny list = %d", response.StatusCode)
	}
}

// TestDenylistTunnelsAndForwards checks the deny list end to end: a CONNECT
// and a plain request for a host it does not block go through, carrying
// bytes untouched, and a blocked one is refused and noted.
func TestDenylistTunnelsAndForwards(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "hello "+r.Host) }))
	t.Cleanup(upstream.Close)
	notice := &bytes.Buffer{}
	e, err := egressFor(Network{Mode: NetworkDenylist, Blocked: []string{"evil.test"}}, notice, true)
	if err != nil {
		t.Fatal(err)
	}
	target := upstream.Listener.Addr().String()
	e.dial = func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, target)
	}
	server := httptest.NewServer(e)
	t.Cleanup(server.Close)
	client := throughProxy(t, server.URL)
	response, err := client.Get("http://anything.test/") //nolint:noctx // a test of the proxy's answer
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "hello anything.test" {
		t.Fatalf("a host not blocked = %d %q", response.StatusCode, body)
	}
	if _, _, status := connect(t, server.Listener.Addr().String(), "anything.test:443"); !strings.Contains(status, " 200 ") {
		t.Fatalf("a CONNECT for a host not blocked = %q", status)
	}
	if _, _, status := connect(t, server.Listener.Addr().String(), "evil.test:443"); !strings.Contains(status, " 403 ") {
		t.Fatalf("a CONNECT for a blocked host = %q", status)
	}
	response, err = client.Get("http://evil.test/") //nolint:noctx // a test of the proxy's answer
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || !strings.Contains(string(body), "evil.test:80 is refused by this stage's network") {
		t.Fatalf("a plain request for a blocked host = %d %q", response.StatusCode, body)
	}
	if !strings.Contains(notice.String(), "hostsandbox: refused a connection to evil.test:443, which this stage's network refuses\n") {
		t.Fatalf("the refusal was not noted: %q", notice.String())
	}
}

// FuzzDenylistNeverAdmitsABlockedName checks that no spelling of a request
// for a blocked host is admitted: whatever the stage asks for, a host the
// proxy admits is a well-formed name that the deny list does not match.
func FuzzDenylistNeverAdmitsABlockedName(f *testing.F) {
	for _, seed := range []string{"evil.test", "EVIL.test.", "evil.test..", " evil.test", "a.bad.test", "evil%2etest", "évil.test"} {
		f.Add(seed, "443")
	}
	e, err := egressFor(Network{Mode: NetworkDenylist, Blocked: []string{"evil.test", "*.bad.test"}}, io.Discard, true)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, host, port string) {
		if !e.admits(host, port, true) {
			return
		}
		normalized := normalizeHost(host)
		if !validHost(normalized) {
			t.Fatalf("admitted %q, which is not a name", host)
		}
		if normalized == "evil.test" || strings.HasSuffix(normalized, ".bad.test") {
			t.Fatalf("admitted %q, which is blocked", host)
		}
	})
}

// FuzzRefuseNonPublic checks that every address the deny list admits is
// public: none is loopback, private, link-local, multicast or unspecified,
// in any of its IPv6 spellings.
func FuzzRefuseNonPublic(f *testing.F) {
	for _, seed := range append(append([]string{}, nonPublic...), public...) {
		f.Add(seed)
	}
	noNetworks(f)
	f.Fuzz(func(t *testing.T, host string) {
		if refuseNonPublic("tcp", net.JoinHostPort(host, "443"), nil) != nil {
			return
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			t.Fatalf("admitted %q, which is not an address", host)
		}
		for _, form := range []netip.Addr{ip, ip.Unmap()} {
			if form.IsLoopback() || form.IsPrivate() || form.IsLinkLocalUnicast() || form.IsLinkLocalMulticast() ||
				form.IsMulticast() || form.IsUnspecified() || form.IsInterfaceLocalMulticast() {
				t.Fatalf("admitted %q", host)
			}
		}
		if ip.Is6() && !ip.Is4In6() {
			if bytes := ip.As16(); bytes[0]&0xe0 != 0x20 && !netip.MustParsePrefix("64:ff9b::/96").Contains(ip) {
				t.Fatalf("admitted %q, outside global unicast", host)
			}
		}
	})
}
