// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

// listenLoopback is a listener on 127.0.0.1 that accepts and closes, so a dial
// that is not refused connects.
func listenLoopback(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	return ln.Addr().String()
}

// TestPublicDialerRefusesWhatIsNotPublic checks that an address written as
// one and a name that resolves to it are refused alike, before any
// connection, though something listens there.
func TestPublicDialerRefusesWhatIsNotPublic(t *testing.T) {
	address := listenLoopback(t)
	_, port, _ := net.SplitHostPort(address)
	dial := PublicDialer(nil)
	for _, target := range []string{address, net.JoinHostPort("localhost", port)} {
		conn, err := dial(context.Background(), "tcp", target)
		if err == nil {
			_ = conn.Close()
			t.Fatalf("dial %s connected", target)
		}
		if !errors.Is(err, ErrNonPublicDestination) {
			t.Fatalf("dial %s = %v, want ErrNonPublicDestination", target, err)
		}
	}
}

// TestPublicDialerAdmitsAnAllowedRange checks that a range the operator
// names is reached though it is not public.
func TestPublicDialerAdmitsAnAllowedRange(t *testing.T) {
	address := listenLoopback(t)
	allow := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	dial := PublicDialer(allow)
	allow[0] = netip.MustParsePrefix("10.0.0.0/8")
	conn, err := dial(context.Background(), "tcp", address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	_ = conn.Close()
}

func TestCheckPublic(t *testing.T) {
	private := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fe80::/10")}
	for _, c := range []struct {
		address string
		allow   []netip.Prefix
		ok      bool
	}{
		{"8.8.8.8:443", nil, true},
		{"[2001:4860::8888]:443", nil, true},
		{"[64:ff9b::808:808]:443", nil, true},
		{"10.0.0.1:443", nil, false},
		{"[::ffff:10.0.0.1]:443", nil, false},
		{"169.254.169.254:80", nil, false},
		{"[fe80::1%en0]:443", nil, false},
		{"10.0.0.1:443", private, true},
		{"[::ffff:10.0.0.1]:443", private, true},
		{"[fe80::1%en0]:443", private, true},
		{"192.168.1.1:443", private, false},
		{"not-an-address", nil, false},
		{"name.test:443", private, false},
	} {
		err := checkPublic(c.address, c.allow)
		if c.ok && err != nil {
			t.Errorf("checkPublic(%q, %v) = %v, want it admitted", c.address, c.allow, err)
		}
		if !c.ok && !errors.Is(err, ErrNonPublicDestination) {
			t.Errorf("checkPublic(%q, %v) = %v, want ErrNonPublicDestination", c.address, c.allow, err)
		}
	}
}

// httptestServer serves gw and answers its URL.
func httptestServer(t *testing.T, gw *Gateway) string {
	t.Helper()
	proxy := httptest.NewServer(gw)
	t.Cleanup(proxy.Close)
	return proxy.URL
}

// recordingDial dials directly and remembers every address it was asked for.
type recordingDial struct {
	mu        sync.Mutex
	addresses []string
}

func (r *recordingDial) dial(ctx context.Context, network, address string) (net.Conn, error) {
	r.mu.Lock()
	r.addresses = append(r.addresses, address)
	r.mu.Unlock()
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

func (r *recordingDial) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.addresses)
}

// TestGateway_DialCarriesEveryUpstreamConnection checks that a terminated
// request and a passthrough tunnel both reach their upstream through Dial.
func TestGateway_DialCarriesEveryUpstreamConnection(t *testing.T) {
	for _, terminate := range []bool{true, false} {
		up := newUpstream(t)
		ca, _, _, _ := GenerateCA("")
		reg := NewRegistry()
		scope := "api.provider.example"
		if terminate {
			scope = up.hostIP(t)
		}
		reg.Set("p-1", []Entry{{Placeholder: []byte("cph_placeholder"), Secret: []byte("sk-real"), AllowedHosts: []string{scope}}})
		rec := &recordingDial{}
		gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}, UpstreamTLS: upstreamRoots(up), Dial: rec.dial}
		proxy := httptestServer(t, gw)
		client := clientThrough(t, proxy, "Bearer t", bothRoots(ca, up))
		body := doGet(t, client, up.server.URL+"/echo", "Bearer cph_placeholder")
		if terminate != strings.Contains(body, "sk-real") {
			t.Fatalf("terminate=%v: upstream saw %q", terminate, body)
		}
		if rec.count() == 0 {
			t.Fatalf("terminate=%v: the upstream was reached without Dial", terminate)
		}
	}
}

// TestGateway_PublicDialerRefusesAnInwardUpstream checks that a secret bound
// to a host that resolves inward does not carry a terminated request there.
func TestGateway_PublicDialerRefusesAnInwardUpstream(t *testing.T) {
	up := newUpstream(t)
	ca, _, _, _ := GenerateCA("")
	reg := NewRegistry()
	reg.Set("p-1", []Entry{{Placeholder: []byte("cph_placeholder"), Secret: []byte("sk-real"), AllowedHosts: []string{up.hostIP(t)}}})
	gw := &Gateway{Registry: reg, CA: ca, Auth: StaticAuth{"Bearer t": "p-1"}, UpstreamTLS: upstreamRoots(up), Dial: PublicDialer(nil)}
	proxy := httptestServer(t, gw)
	client := clientThrough(t, proxy, "Bearer t", bothRoots(ca, up))
	req, _ := http.NewRequest("GET", up.server.URL+"/echo", nil)
	req.Header.Set("Authorization", "Bearer cph_placeholder")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "sk-real") {
		t.Fatalf("status %d, body %q; want 502 and no upstream answer", resp.StatusCode, body)
	}
}
