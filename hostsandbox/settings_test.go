// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestEveryDeniedPathReachesTheSettings checks that every entry in the deny
// table reaches the settings file, expanded against the home directory. A rule
// like this fails when a default widens by accident, so the table is asserted
// rather than trusted.
func TestEveryDeniedPathReachesTheSettings(t *testing.T) {
	home := "/Users/x"
	settings := Render(Profile{
		Home:       home,
		Reads:      []string{"/Users/x/.claude", "/s/workspace"},
		Writes:     []string{"/s/workspace", "/s/tmp"},
		Denies:     []string{"~/.config/consumer", "/Users/x/.claude/CLAUDE.md"},
		DenyWrites: []string{"/s/log"},
		Network:    Network{Mode: NetworkNone},
	})
	for _, entry := range AlwaysDenyRead {
		want := strings.Replace(entry, "~", home, 1)
		if !slices.Contains(settings.Filesystem.DenyRead, want) {
			t.Errorf("deny table entry %q did not reach the settings", want)
		}
	}
	for _, want := range []string{home, "/Users/x/.config/consumer", "/Users/x/.claude/CLAUDE.md", "/Users/x/.env"} {
		if !slices.Contains(settings.Filesystem.DenyRead, want) {
			t.Errorf("%s is readable: %v", want, settings.Filesystem.DenyRead)
		}
	}
	if !slices.Contains(settings.Filesystem.AllowRead, "/Users/x/.claude") {
		t.Errorf("the allowed read inside the home directory is missing: %v", settings.Filesystem.AllowRead)
	}
	if !slices.Contains(settings.Filesystem.DenyWrite, "/s/log") {
		t.Errorf("the log directory is writable: %+v", settings.Filesystem)
	}
	body, err := settings.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("the settings file is not valid JSON: %v", err)
	}
	if _, ok := decoded["filesystem"]; !ok {
		t.Fatalf("the settings file has no filesystem section:\n%s", body)
	}
	// Two profiles with the same grants in a different order render the same
	// bytes, so a settings file is comparable across runs.
	again, _ := Render(Profile{
		Home:       home,
		Reads:      []string{"/s/workspace", "/Users/x/.claude", "/s/workspace"},
		Writes:     []string{" /s/tmp ", "/s/workspace", ""},
		Denies:     []string{"/Users/x/.claude/CLAUDE.md", "~/.config/consumer"},
		DenyWrites: []string{"/s/log"},
		Network:    Network{Mode: NetworkNone},
	}).Encode()
	if string(again) != string(body) {
		t.Fatalf("the same grants rendered differently:\n%s\n%s", body, again)
	}
}

// TestNetworkModesRender checks that the network modes render as distinct
// policies and that none of them leaves egress unspecified.
func TestNetworkModesRender(t *testing.T) {
	none := Render(Profile{Network: Network{Mode: NetworkNone}})
	if len(none.Network.AllowedDomains) != 0 || none.Network.TLSTerminate != nil {
		t.Errorf("a closed sandbox allows %v with TLS %v", none.Network.AllowedDomains, none.Network.TLSTerminate)
	}
	list := Render(Profile{Network: Network{
		Mode: NetworkAllowlist, Domains: []string{"github.com", "arxiv.org", "github.com"}, Passthrough: []string{"pypi.org"},
	}})
	if !slices.Equal(list.Network.AllowedDomains, []string{"arxiv.org", "github.com"}) {
		t.Errorf("allowlist = %v", list.Network.AllowedDomains)
	}
	// TLS termination is declared whenever a domain is allowed, because srt
	// publishes its certificate authority to the trust variables only then.
	if list.Network.TLSTerminate == nil || !slices.Equal(list.Network.TLSTerminate.ExcludeDomains, []string{"pypi.org"}) {
		t.Errorf("TLS termination = %+v", list.Network.TLSTerminate)
	}
	empty := Render(Profile{Network: Network{Mode: NetworkAllowlist}})
	if empty.Network.TLSTerminate == nil || len(empty.Network.TLSTerminate.ExcludeDomains) != 0 {
		t.Errorf("an allowlist with nothing to exclude did not declare termination: %+v", empty.Network.TLSTerminate)
	}
	// There is no open mode. srt refuses a wildcard, so open renders as
	// closed rather than as a profile srt rejects.
	open := Render(Profile{Network: Network{Mode: NetworkOpen}})
	if len(open.Network.AllowedDomains) != 0 {
		t.Errorf("open mode rendered %v", open.Network.AllowedDomains)
	}
	if list.Network.AllowAllUnixSockets || list.Network.AllowLocalBinding {
		t.Error("the network policy leaves a hole open by default")
	}
	// Empty lists encode as [] rather than null, which srt reads as absent.
	body, _ := none.Encode()
	if !strings.Contains(string(body), `"allowedDomains": []`) || !strings.Contains(string(body), `"deniedDomains": []`) {
		t.Errorf("empty lists did not encode as arrays:\n%s", body)
	}
}

// TestExpandKeepsWhatItCannotExpand checks that a deny entry never disappears:
// with no home directory the entry stays as written, and a path that only
// starts with a tilde is not a home-relative path.
func TestExpandKeepsWhatItCannotExpand(t *testing.T) {
	for _, c := range []struct{ home, path, want string }{
		{"", "~/.ssh", "~/.ssh"},
		{"", "~", "~"},
		{"/h", "~", "/h"},
		{"/h", "~/.ssh", "/h/.ssh"},
		{"/h", "~user/.ssh", "~user/.ssh"},
		{"/h", "/abs", "/abs"},
	} {
		if got := expand(c.home, c.path); got != c.want {
			t.Errorf("expand(%q, %q) = %q, want %q", c.home, c.path, got, c.want)
		}
	}
	settings := Render(Profile{})
	if !slices.Contains(settings.Filesystem.DenyRead, "~/.ssh") || !slices.Contains(settings.Filesystem.DenyRead, "~") {
		t.Errorf("with no home the deny table was dropped: %v", settings.Filesystem.DenyRead)
	}
}
