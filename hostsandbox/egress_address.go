// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"syscall"
)

// errNonPublicDestination is a destination a deny list never reaches: this
// machine, a network it is on, or an address that is not public.
var errNonPublicDestination = errors.New("the destination is this machine, a local network or an address that is not public")

// refusedIPv4 are the IPv4 ranges a deny list refuses: this machine and
// "this network", private networks, the carrier-grade NAT range (which
// tailnets use for the person's other machines), link-local addresses with
// the cloud metadata endpoint, the special-purpose, benchmarking and
// documentation ranges, multicast, and the reserved range with the
// broadcast address. The benchmarking range, 198.18.0.0/15, is where a proxy
// or VPN app's fake-IP mode answers every name from before it resolves and
// connects to the name itself, wherever the name's own servers point it, so
// the address the proxy checks says nothing of where the connection goes.
var refusedIPv4 = prefixes(
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12",
	"192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
	"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)

// IPv6 is admitted only from global unicast, 2000::/3, less the ranges in
// refusedIPv6. Outside it lie the loopback and unspecified addresses, the
// IPv4-compatible form, unique local, link-local and the deprecated
// site-local addresses, multicast, and the local-use NAT64 prefix, so all of
// them are refused. Inside it, refusedIPv6 are the IETF's protocol
// assignments with Teredo, and the documentation prefixes.
var (
	globalUnicast = netip.MustParsePrefix("2000::/3")
	refusedIPv6   = prefixes("2001::/23", "2001:db8::/32", "3fff::/20")
)

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

// refuseNonPublic is a deny list's check of the address a name resolved to,
// made by the dialer before each connection is opened, so a name that
// resolves elsewhere on its next lookup is checked again. It refuses an
// address that is not public, one with a zone, and one on a network this
// machine is on.
func refuseNonPublic(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("check destination %q: %w", address, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" || !publicAddress(ip) {
		return fmt.Errorf("%w: %s", errNonPublicDestination, host)
	}
	networks, err := localNetworks()
	if err != nil {
		return fmt.Errorf("%w: reading this machine's networks to check %s: %w", errNonPublicDestination, host, err)
	}
	ip = reached(ip)
	for _, network := range networks {
		if network.Contains(ip) {
			return fmt.Errorf("%w: %s", errNonPublicDestination, host)
		}
	}
	return nil
}

// reached is the address a connection to ip reaches: the IPv4 address an
// IPv4-mapped address maps, and the one the well-known NAT64 prefix
// translates to; ip itself otherwise.
func reached(ip netip.Addr) netip.Addr {
	ip = ip.Unmap()
	if ip.Is6() && nat64.Contains(ip) {
		bytes := ip.As16()
		return netip.AddrFrom4([4]byte(bytes[12:16]))
	}
	return ip
}

// publicAddress reports whether an address without a zone is public.
func publicAddress(ip netip.Addr) bool {
	ip = reached(ip)
	if ip.Is6() {
		switch {
		case sixToFour.Contains(ip):
			bytes := ip.As16()
			ip = netip.AddrFrom4([4]byte(bytes[2:6]))
		case !globalUnicast.Contains(ip):
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

// localInterface is what the check reads of one network interface.
type localInterface struct {
	flags net.Flags
	addrs []net.Addr
}

// interfaces lists this machine's network interfaces. A test replaces it.
var interfaces = func() ([]localInterface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]localInterface, 0, len(list))
	for _, item := range list {
		addrs, err := item.Addrs()
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", item.Name, err)
		}
		out = append(out, localInterface{flags: item.Flags, addrs: addrs})
	}
	return out, nil
}

// sitePrefix is how much of a global IPv6 address on this machine's Wi-Fi or
// Ethernet a deny list refuses: the /48 holding it, the most a provider
// delegates to one site, so the person's other networks, which a router
// numbers from the same delegation, are refused with the one this machine
// is on.
const sitePrefix = 48

// localNetworks are the networks a deny list refuses because this machine
// is on them, read when each connection is checked: the whole network of a
// broadcast interface, its Wi-Fi or Ethernet, whose devices hold global
// IPv6 addresses under this machine's own prefix, widened for IPv6 to the
// sitePrefix holding it; and every address of this machine's own, on which
// a service it runs on all interfaces answers. A point-to-point interface, a
// VPN's or a proxy app's tunnel, adds only its own address, and so does a
// network wider than an IPv4 /8 or an IPv6 /32, which no interface of a
// real network is on.
func localNetworks() ([]netip.Prefix, error) {
	list, err := interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, item := range list {
		whole := item.flags&net.FlagBroadcast != 0 && item.flags&net.FlagPointToPoint == 0
		for _, addr := range item.addrs {
			var ip net.IP
			var mask net.IPMask
			switch value := addr.(type) {
			case *net.IPNet:
				ip, mask = value.IP, value.Mask
			case *net.IPAddr:
				ip = value.IP
			default:
				continue
			}
			address, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			address = address.Unmap()
			bits := address.BitLen()
			if ones, size := mask.Size(); whole && size == bits && ones >= bits/4 {
				bits = ones
				if address.Is6() && globalUnicast.Contains(address) {
					bits = min(bits, sitePrefix)
				}
			}
			out = append(out, netip.PrefixFrom(address, bits).Masked())
		}
	}
	return out, nil
}

// hostNameMax is the longest host name DNS carries, and labelMax its longest
// label.
const (
	hostNameMax = 253
	labelMax    = 63
)

// validHost reports whether a normalized host is an address without a zone
// or a host name: at most hostNameMax characters, in labels of 1 to
// labelMax lower-case ASCII letters, digits, hyphens and underscores that
// neither begin nor end with a hyphen. An IDN is a name in its xn-- form. A
// name whose last label is a number, in decimal or in 0x hexadecimal, is
// not one: no top-level domain is a number, and a resolver reads such a
// name, 2130706433, 0x7f.0.0.1 or 127.0.0.01, as an address, which would
// pass a deny list's entry for that address spelled the usual way.
func validHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == ""
	}
	if host == "" || len(host) > hostNameMax {
		return false
	}
	last := ""
	for label := range strings.SplitSeq(host, ".") {
		if label == "" || len(label) > labelMax || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := range len(label) {
			if c := label[i]; (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				return false
			}
		}
		last = label
	}
	return !numeric(last)
}

// numeric reports whether a label is a number in decimal, or 0x followed by
// hexadecimal digits or none.
func numeric(label string) bool {
	digits, base := label, "0123456789"
	if rest, ok := strings.CutPrefix(label, "0x"); ok {
		digits, base = rest, "0123456789abcdef"
		if digits == "" {
			return true
		}
	}
	return strings.Trim(digits, base) == ""
}

// reportable reports whether a normalized host may be reported as refused:
// a well-formed name, or an address in the canonical form of the address it
// reaches, so a prompt shows the address a connection would reach, and the
// spellings of one address are not refusals of their own. Another spelling
// is not reported, even under an allowlist, whose entries match spellings,
// that would admit it.
func reportable(host string) bool {
	if ip, ok := reachedAddress(host); ok {
		return ip.String() == host
	}
	return validHost(host)
}

// reachedAddress is an address host as the address a connection to it
// reaches, in its canonical form, or false when the host is not an address
// without a zone. A deny list matches addresses in this form, so neither a
// spelling of a blocked address nor its NAT64 form gets past it.
func reachedAddress(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(host)
	if err != nil || ip.Zone() != "" {
		return netip.Addr{}, false
	}
	return reached(ip), true
}
