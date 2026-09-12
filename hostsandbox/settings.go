// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"latere.ai/x/pkg/uniq"
)

// Settings is srt's configuration file. The field names are srt's own, so this
// type is the only place a change in that format is tracked.
type Settings struct {
	Network    NetworkSettings    `json:"network"`
	Filesystem FilesystemSettings `json:"filesystem"`
}

// NetworkSettings is the egress policy. srt denies everything by default and
// allows named domains through a host proxy.
type NetworkSettings struct {
	AllowedDomains []string `json:"allowedDomains"`
	DeniedDomains  []string `json:"deniedDomains"`
	// TLSTerminate configures inspection. srt intercepts egress with its own
	// certificate authority and publishes that authority to the per-tool
	// trust variables only when this block is present.
	TLSTerminate *TLSSettings `json:"tlsTerminate,omitempty"`
	// AllowLocalBinding stays false. A stage that binds a local port is
	// communicating with something outside the sandbox's control.
	AllowLocalBinding bool `json:"allowLocalBinding"`
	// AllowAllUnixSockets stays false. A unix socket bypasses the boundary
	// and reaches whatever service is listening on it.
	AllowAllUnixSockets bool `json:"allowAllUnixSockets"`
}

// TLSSettings names the domains whose egress is not inspected.
type TLSSettings struct {
	ExcludeDomains []string `json:"excludeDomains"`
}

// FilesystemSettings is the path policy. srt treats allowRead as an override
// of denyRead, and denyWrite as an override of allowWrite, so the read and
// write halves are expressed in opposite directions.
type FilesystemSettings struct {
	DenyRead   []string `json:"denyRead"`
	AllowRead  []string `json:"allowRead"`
	AllowWrite []string `json:"allowWrite"`
	DenyWrite  []string `json:"denyWrite"`
}

// AlwaysDenyRead lists the credential paths denied to every stage regardless
// of what else is allowed. Entries are expanded against the home directory.
// It is a table checked by a test rather than a comment, because a rule like
// this fails when a default widens by accident. A consumer with credentials of
// its own appends them through Profile.Denies.
var AlwaysDenyRead = []string{
	"~/.ssh",
	"~/.aws",
	"~/.config/gcloud",
	"~/.kube",
	"~/.netrc",
	"~/.gnupg",
	"~/.docker/config.json",
	"~/.git-credentials",
	"~/.npmrc",
	"~/.pypirc",
	"~/.env",
}

// Profile is what one stage may access, before it is rendered into srt's
// settings file.
type Profile struct {
	// Home is the operator's home directory. The whole directory is denied,
	// so that only the paths in Reads are readable inside it. Empty leaves
	// "~" entries unexpanded and denies nothing beyond Denies.
	Home string
	// Reads are the paths the stage may read.
	Reads []string
	// Writes are the paths the stage may write.
	Writes []string
	// Denies are paths withheld from a read grant that would otherwise cover
	// them. A leading "~" is expanded against Home.
	Denies []string
	// DenyWrites are paths inside a writable tree that stay read-only.
	DenyWrites []string
	// Network is the egress policy.
	Network Network
}

// Render turns a profile into srt's settings file.
//
// The read and write halves run in opposite directions because srt's
// precedence does. denyRead is broad and allowRead makes exceptions to it, so
// the whole home directory is denied and the profile's reads are allowed back.
// allowWrite is narrow and denyWrite makes exceptions to it, so only the
// profile's writes are listed and DenyWrites are denied inside them.
//
// Only NetworkAllowlist yields allowed domains. NetworkOpen renders as no
// egress: srt refuses a wildcard ("Overly broad patterns like *.com or * are
// not allowed"), so a consumer that needs open egress must not select this
// driver, and the Driver's Capabilities say so.
func Render(profile Profile) Settings {
	denyRead := append(append([]string{"~"}, AlwaysDenyRead...), profile.Denies...)
	settings := Settings{
		Filesystem: FilesystemSettings{
			DenyRead:   expandAll(profile.Home, denyRead),
			AllowRead:  sorted(profile.Reads),
			AllowWrite: sorted(profile.Writes),
			DenyWrite:  sorted(profile.DenyWrites),
		},
		Network: NetworkSettings{AllowedDomains: []string{}, DeniedDomains: []string{}},
	}
	if profile.Network.Mode == NetworkAllowlist {
		settings.Network.AllowedDomains = sorted(profile.Network.Domains)
		// Declared even with nothing to exclude: without it srt publishes
		// no trust variables and every HTTPS client rejects the proxy,
		// which presents as a network failure rather than a trust failure.
		settings.Network.TLSTerminate = &TLSSettings{ExcludeDomains: sorted(profile.Network.Passthrough)}
	}
	return settings
}

// Encode renders the settings as the file srt reads.
func (s Settings) Encode() ([]byte, error) {
	body, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode sandbox settings: %w", err)
	}
	return append(body, '\n'), nil
}

// expandAll resolves a leading ~ against home. A path that cannot be expanded
// is kept as written rather than dropped, because a deny entry that silently
// disappears is worse than one that matches nothing.
func expandAll(home string, paths []string) []string {
	expanded := make([]string, 0, len(paths))
	for _, path := range paths {
		expanded = append(expanded, expand(home, path))
	}
	return sorted(expanded)
}

func expand(home, path string) string {
	switch {
	case home == "":
		return path
	case path == "~":
		return home
	case strings.HasPrefix(path, "~/"):
		return filepath.Join(home, path[2:])
	default:
		return path
	}
}

// sorted trims, drops empties, removes duplicates and sorts, so two profiles
// with the same grants render byte-for-byte the same file.
func sorted(values []string) []string {
	out := uniq.Strings(values)
	slices.Sort(out)
	return out
}
