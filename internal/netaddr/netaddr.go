// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package netaddr decides whether an address is on the public internet. It
// is the one rule the paths that dial for a workload share, so a deny-list
// stage and an egress gateway refuse the same addresses.
package netaddr

import "net/netip"

// refusedIPv4 are the IPv4 ranges that are not public: this machine and
// "this network", private networks, the carrier-grade NAT range (which
// tailnets use for the person's other machines), link-local addresses with
// the cloud metadata endpoint, the special-purpose, benchmarking and
// documentation ranges, multicast, and the reserved range with the
// broadcast address. The benchmarking range, 198.18.0.0/15, is where a proxy
// or VPN app's fake-IP mode answers every name from before it resolves and
// connects to the name itself, wherever the name's own servers point it, so
// the address a dialer checks says nothing of where the connection goes.
var refusedIPv4 = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

// GlobalUnicast is the only IPv6 space that is public, less refusedIPv6.
// Outside it lie the loopback and unspecified addresses, the IPv4-compatible
// form, unique local, link-local and the deprecated site-local addresses,
// multicast, and the local-use NAT64 prefix, so none of them is public.
var GlobalUnicast = netip.MustParsePrefix("2000::/3")

// refusedIPv6 are the ranges inside GlobalUnicast that are not public: the
// IETF's protocol assignments with Teredo, and the documentation prefixes.
var refusedIPv6 = prefixes("2001::/23", "2001:db8::/32", "3fff::/20")

// The IPv6 forms that carry an IPv4 address, each decided by the address it
// carries: the well-known NAT64 prefix holds it in its last 32 bits, and
// 6to4 in the 32 bits after its first 16. An IPv4-mapped address is read as
// the IPv4 address it maps.
var (
	nat64     = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour = netip.MustParsePrefix("2002::/16")
)

func prefixes(values ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		out = append(out, netip.MustParsePrefix(value))
	}
	return out
}

// Reached is the address a connection to ip reaches: the IPv4 address an
// IPv4-mapped address maps, and the one the well-known NAT64 prefix
// translates to; ip itself otherwise.
func Reached(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() && nat64.Contains(ip) {
		bytes := ip.As16()
		return netip.AddrFrom4([4]byte(bytes[12:16]))
	}
	return ip
}

// Public reports whether an address without a zone is public. An address
// with a zone names a link, and is not.
func Public(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = Reached(ip)
	if ip.Is6() {
		switch {
		case sixToFour.Contains(ip):
			bytes := ip.As16()
			ip = netip.AddrFrom4([4]byte(bytes[2:6]))
		case !GlobalUnicast.Contains(ip):
			return false
		default:
			return !inAny(refusedIPv6, ip)
		}
	}
	return !inAny(refusedIPv4, ip)
}

func inAny(ranges []netip.Prefix, ip netip.Addr) bool {
	for _, prefix := range ranges {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
