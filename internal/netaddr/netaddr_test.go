// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package netaddr

import (
	"net/netip"
	"testing"
)

// nonPublic is addresses that are not public, in every IPv6 spelling that
// carries an IPv4 address.
var nonPublic = []string{
	// This machine, and "this network".
	"127.0.0.1", "127.255.255.255", "0.0.0.0", "0.255.255.255", "::1", "::",
	// Link-local, the cloud metadata endpoint among it.
	"169.254.169.254", "169.254.0.0", "169.254.255.255", "fe80::1", "febf:ffff::1",
	// Private networks, the carrier-grade NAT range tailnets use, and
	// unique local addresses.
	"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255", "192.168.0.0", "192.168.255.255",
	"100.64.0.0", "100.127.255.255", "fc00::", "fd7a:115c:a1e0::1", "fdff:ffff::1",
	// Special purpose, documentation and benchmarking ranges.
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
	// A zone names a link.
	"fe80::1%en0", "2001:4860::8888%en0",
}

// public is addresses that are public, those just outside a refused range
// among them.
var public = []string{
	"8.8.8.8", "1.1.1.1", "9.255.255.255", "11.0.0.0", "100.63.255.255", "100.128.0.0", "169.253.255.255",
	"169.255.0.0", "172.15.255.255", "172.32.0.0", "192.167.255.255", "192.169.0.0", "198.17.255.255", "198.20.0.0", "223.255.255.255",
	"2001:4860:4860::8888", "2606:4700:4700::1111", "2a00:1450::1", "2001:200::1", "3fff:1000::1", "3ffe::1",
	"::ffff:8.8.8.8", "64:ff9b::808:808", "2002:808:808::1",
}

func TestPublic(t *testing.T) {
	for _, value := range nonPublic {
		if Public(netip.MustParseAddr(value)) {
			t.Errorf("Public(%s) = true", value)
		}
	}
	for _, value := range public {
		if !Public(netip.MustParseAddr(value)) {
			t.Errorf("Public(%s) = false", value)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("the zero address is public")
	}
}

func TestReached(t *testing.T) {
	for in, want := range map[string]string{
		"::ffff:10.0.0.1":    "10.0.0.1",
		"64:ff9b::808:808":   "8.8.8.8",
		"8.8.8.8":            "8.8.8.8",
		"2001:4860::8888":    "2001:4860::8888",
		"64:ff9b:1::a00:1":   "64:ff9b:1::a00:1",
		"::ffff:127.0.0.1":   "127.0.0.1",
		"64:ff9b::a9fe:a9fe": "169.254.169.254",
	} {
		if got := Reached(netip.MustParseAddr(in)); got != netip.MustParseAddr(want) {
			t.Errorf("Reached(%s) = %s, want %s", in, got, want)
		}
	}
}

// FuzzPublic checks that no address Public admits is loopback, private,
// link-local, multicast or unspecified, in any of its IPv6 spellings, or
// outside global unicast.
func FuzzPublic(f *testing.F) {
	for _, seed := range append(append([]string{}, nonPublic...), public...) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		ip, err := netip.ParseAddr(value)
		if err != nil || !Public(ip) {
			return
		}
		for _, form := range []netip.Addr{ip, ip.Unmap(), Reached(ip)} {
			if form.IsLoopback() || form.IsPrivate() || form.IsLinkLocalUnicast() || form.IsLinkLocalMulticast() ||
				form.IsMulticast() || form.IsUnspecified() || form.IsInterfaceLocalMulticast() {
				t.Fatalf("Public(%s) = true", value)
			}
		}
		if ip.Is6() && !ip.Is4In6() {
			if bytes := ip.As16(); bytes[0]&0xe0 != 0x20 && !nat64.Contains(ip) {
				t.Fatalf("Public(%s) = true, outside global unicast", value)
			}
		}
	})
}
