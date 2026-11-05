// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package clientip works out the address of the caller of an HTTP request
// that may have passed through reverse proxies. The rule it enforces: a
// forwarded header is believed only when the connection's peer is a trusted
// proxy, and then only up to the nearest hop that is not trusted, so a caller
// cannot choose the address it is identified (or rate limited) under.
//
// Every address returned is in one canonical form: no port, no brackets, and
// an IPv4-mapped IPv6 address unmapped, so one client has one key whichever
// way the network stack presented it.
package clientip

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

// Peer returns the address of the connection's peer from r.RemoteAddr, with
// the port and brackets removed and an IPv4-mapped address unmapped. When
// RemoteAddr is not an address, the host part is returned as it is.
func Peer(r *http.Request) string {
	host := hostOf(r.RemoteAddr)
	if a, err := netip.ParseAddr(host); err == nil {
		return a.Unmap().String()
	}
	return host
}

// Address returns the caller's address. When the peer is not inside one of
// trusted, that is Peer(r), and every forwarded header is ignored. Otherwise
// the X-Forwarded-For entries (all header lines, comma separated) are walked
// from the right and the first entry outside trusted is returned, unmapped.
// An entry that is not an address ends the walk with Peer(r), since a proxy
// that wrote garbage cannot be trusted further. When every entry is trusted
// or there are none, the answer is Peer(r).
func Address(r *http.Request, trusted []netip.Prefix) string {
	peer := Peer(r)
	addr, err := netip.ParseAddr(peer)
	if err != nil || !inRanges(addr, trusted) {
		return peer
	}
	var entries []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for e := range strings.SplitSeq(h, ",") {
			if e = strings.TrimSpace(e); e != "" {
				entries = append(entries, e)
			}
		}
	}
	for _, e := range slices.Backward(entries) {
		a, err := netip.ParseAddr(hostOf(e))
		if err != nil {
			return peer
		}
		if !inRanges(a, trusted) {
			return a.Unmap().String()
		}
	}
	return peer
}

// ParseTrusted reads a comma separated list of CIDR prefixes and bare
// addresses (a bare address is a single-address prefix). Entries are trimmed
// and empty entries skipped; an empty list is (nil, nil). Prefixes are
// masked, and an IPv4-mapped IPv6 entry is stored as the IPv4 range it
// stands for, since addresses are matched unmapped. An entry that is neither
// a prefix nor an address is an error naming it.
func ParseTrusted(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for s := range strings.SplitSeq(list, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				return nil, fmt.Errorf("clientip: %q is neither a CIDR prefix nor an address", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		out = append(out, unmapPrefix(p).Masked())
	}
	return out, nil
}

// unmapPrefix turns ::ffff:a.b.c.d/n (n >= 96) into a.b.c.d/(n-96).
func unmapPrefix(p netip.Prefix) netip.Prefix {
	a := p.Addr()
	if a.Is4In6() && p.Bits() >= 96 && a.Zone() == "" {
		return netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p
}

// hostOf strips a port from host:port and the brackets from an IPv6
// literal; a bare host is returned as it is.
func hostOf(s string) string {
	if host, _, err := net.SplitHostPort(s); err == nil {
		return host
	}
	return strings.Trim(s, "[]")
}

func inRanges(a netip.Addr, ranges []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range ranges {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
