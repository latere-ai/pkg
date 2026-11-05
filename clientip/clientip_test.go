// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package clientip

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func req(remote string, xff ...string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = remote
	for _, v := range xff {
		r.Header.Add("X-Forwarded-For", v)
	}
	return r
}

func TestPeer(t *testing.T) {
	for _, c := range []struct{ remote, want string }{
		{"203.0.113.9:4000", "203.0.113.9"},
		{"[2001:db8::1]:443", "2001:db8::1"},
		{"[::ffff:203.0.113.9]:443", "203.0.113.9"},
		{"::ffff:203.0.113.9", "203.0.113.9"},
		{"2001:db8::1", "2001:db8::1"},
		{"[2001:db8::1]", "2001:db8::1"},
		{"pipe", "pipe"},
		{"host:80", "host"},
		{"", ""},
	} {
		if got := Peer(req(c.remote)); got != c.want {
			t.Errorf("Peer(%q) = %q, want %q", c.remote, got, c.want)
		}
	}
}

func TestAddress(t *testing.T) {
	trusted, err := ParseTrusted("10.0.0.0/8, 192.168.1.1, fd00::/8")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		remote string
		xff    []string
		trust  []netip.Prefix
		want   string
	}{
		{"no trust ignores header", "203.0.113.9:1", []string{"1.2.3.4"}, nil, "203.0.113.9"},
		{"untrusted peer ignores header", "203.0.113.9:1", []string{"1.2.3.4"}, trusted, "203.0.113.9"},
		{"trusted peer, one hop", "10.0.0.1:1", []string{"1.2.3.4"}, trusted, "1.2.3.4"},
		{"rightmost untrusted wins", "10.0.0.1:1", []string{"9.9.9.9, 1.2.3.4, 10.0.0.2"}, trusted, "1.2.3.4"},
		{"spoofed left entry is skipped", "10.0.0.1:1", []string{"6.6.6.6", "1.2.3.4"}, trusted, "1.2.3.4"},
		{"several lines and spaces", "10.0.0.1:1", []string{"6.6.6.6,  ", " 1.2.3.4 , 10.1.1.1", "192.168.1.1"}, trusted, "1.2.3.4"},
		{"port removed", "10.0.0.1:1", []string{"1.2.3.4:5555"}, trusted, "1.2.3.4"},
		{"brackets and port removed", "10.0.0.1:1", []string{"[2001:db8::7]:99"}, trusted, "2001:db8::7"},
		{"brackets removed", "10.0.0.1:1", []string{"[2001:db8::7]"}, trusted, "2001:db8::7"},
		{"mapped entry unmapped", "10.0.0.1:1", []string{"::ffff:203.0.113.9"}, trusted, "203.0.113.9"},
		{"mapped trusted entry skipped", "10.0.0.1:1", []string{"1.2.3.4, ::ffff:10.0.0.9"}, trusted, "1.2.3.4"},
		{"mapped trusted peer", "[::ffff:10.0.0.1]:1", []string{"1.2.3.4"}, trusted, "1.2.3.4"},
		{"mapped untrusted peer unmapped", "[::ffff:203.0.113.9]:1", []string{"1.2.3.4"}, trusted, "203.0.113.9"},
		{"garbage ends the walk", "10.0.0.1:1", []string{"1.2.3.4, nonsense, 10.0.0.2"}, trusted, "10.0.0.1"},
		{"all trusted", "10.0.0.1:1", []string{"10.0.0.2, 192.168.1.1"}, trusted, "10.0.0.1"},
		{"no header", "10.0.0.1:1", nil, trusted, "10.0.0.1"},
		{"ipv6 trusted peer", "[fd00::1]:1", []string{"1.2.3.4"}, trusted, "1.2.3.4"},
		{"unparsable peer", "pipe", []string{"1.2.3.4"}, trusted, "pipe"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Address(req(c.remote, c.xff...), c.trust); got != c.want {
				t.Errorf("Address = %q, want %q", got, c.want)
			}
		})
	}
}

func TestParseTrusted(t *testing.T) {
	got, err := ParseTrusted(" 10.1.2.3/8 , ,192.168.1.1,2001:db8::1, ::ffff:172.16.0.0/108, ::ffff:1.2.3.4,fd00::/8,")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.0.0.0/8", "192.168.1.1/32", "2001:db8::1/128", "172.16.0.0/12", "1.2.3.4/32", "fd00::/8"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i, p := range got {
		if p.String() != want[i] {
			t.Errorf("entry %d = %s, want %s", i, p, want[i])
		}
	}
	for _, empty := range []string{"", "  ", " , ,"} {
		p, err := ParseTrusted(empty)
		if p != nil || err != nil {
			t.Errorf("ParseTrusted(%q) = %v, %v; want nil, nil", empty, p, err)
		}
	}
	_, err = ParseTrusted("10.0.0.0/8, bogus/9")
	if err == nil || !strings.Contains(err.Error(), "bogus/9") {
		t.Errorf("error %v does not name the entry", err)
	}
}

func TestMappedPrefixMatchesPlainAddress(t *testing.T) {
	trusted, err := ParseTrusted("::ffff:10.0.0.0/104")
	if err != nil {
		t.Fatal(err)
	}
	if got := Address(req("10.9.9.9:1", "1.2.3.4"), trusted); got != "1.2.3.4" {
		t.Errorf("got %q", got)
	}
}

func FuzzAddress(f *testing.F) {
	f.Add("10.0.0.1:80", "1.2.3.4, 10.0.0.2")
	f.Add("[::ffff:10.0.0.1]:80", "[::ffff:1.2.3.4]:5")
	f.Add("pipe", "garbage")
	f.Add("", "")
	f.Add("[fd00::1]:1", "fe80::1%eth0, ,,")
	trusted, _ := ParseTrusted("10.0.0.0/8,fd00::/8")
	f.Fuzz(func(t *testing.T, remote, header string) {
		if strings.ContainsAny(header, "\r\n") {
			return
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = remote
		r.Header["X-Forwarded-For"] = []string{header}
		got := Address(r, trusted)
		if got == Peer(r) {
			return
		}
		if _, err := netip.ParseAddr(got); err != nil {
			t.Fatalf("Address = %q, neither the peer nor an address", got)
		}
	})
}

func FuzzParseTrusted(f *testing.F) {
	f.Add("10.0.0.0/8, 192.168.1.1")
	f.Add("::ffff:10.0.0.0/104,,")
	f.Add("bogus")
	f.Add("")
	f.Fuzz(func(t *testing.T, list string) {
		ps, err := ParseTrusted(list)
		if err != nil {
			if ps != nil {
				t.Fatal("prefixes returned with an error")
			}
			return
		}
		for _, p := range ps {
			if !p.IsValid() || p != p.Masked() {
				t.Fatalf("bad prefix %v", p)
			}
		}
	})
}
