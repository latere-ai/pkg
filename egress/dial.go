// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"latere.ai/x/pkg/internal/netaddr"
)

// ErrNonPublicDestination is what a [PublicDialer] answers for an address it
// does not connect to. A caller tells it apart from an upstream that did not
// answer with [errors.Is].
var ErrNonPublicDestination = errors.New("egress: the destination is not a public address")

// PublicDialer returns a dial function that connects only to a public
// address, or to one inside allow. A gateway sits on its operator's network,
// so without it a workload could reach that network through the gateway:
// a private service, a cloud's metadata endpoint, the gateway's own
// neighbors. Public means the global internet: not loopback, private,
// carrier-grade NAT, link-local, unique local, multicast, reserved,
// benchmarking or documentation space, in any IPv6 form that carries an IPv4
// address.
//
// The check is made on the address each connection dials, after its name
// was resolved, so a name that resolves inward is refused like an address
// written as one, and so is a name whose next lookup answers differently.
// allow holds the non-public ranges an operator means workloads to reach,
// such as a registry on the same private network; nil admits none.
func PublicDialer(allow []netip.Prefix) func(ctx context.Context, network, address string) (net.Conn, error) {
	ranges := append([]netip.Prefix(nil), allow...)
	d := &net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
		return checkPublic(address, ranges)
	}}
	return d.DialContext
}

// checkPublic admits a dialed host:port whose address is public or inside
// allow.
func checkPublic(address string, allow []netip.Prefix) error {
	dialed, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %q is not an address and port", ErrNonPublicDestination, address)
	}
	ip := dialed.Addr()
	if netaddr.Public(ip) {
		return nil
	}
	reached := netaddr.Reached(ip.WithZone(""))
	for _, prefix := range allow {
		if prefix.Contains(reached) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrNonPublicDestination, ip)
}
