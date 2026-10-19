// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package hostsandbox

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
)

// sandboxExec is macOS's own program that runs a command under a Seatbelt
// profile. It is named by its absolute path and never looked up on PATH: a
// program of that name planted earlier on PATH would run the stage under no
// sandbox at all. A test points it at a stand-in.
var sandboxExec = "/usr/bin/sandbox-exec"

// seatbeltServices are the Mach services a stage may look up. A program on
// macOS reaches the user and group database, the system log, preferences,
// its temporary directory and TLS certificate checks through these, and runs
// without the rest. Everything else a Mach lookup could reach (the
// pasteboard, the keychain's user interface, file system events naming
// paths outside the grants, other applications) stays denied.
var seatbeltServices = []string{
	"com.apple.bsd.dirhelper",
	"com.apple.cfprefsd.agent",
	"com.apple.cfprefsd.daemon",
	"com.apple.logd",
	"com.apple.SecurityServer",
	"com.apple.system.logger",
	"com.apple.system.notification_center",
	"com.apple.system.opendirectoryd.libinfo",
	"com.apple.trustd.agent",
}

// seatbeltDevices are the device files a stage may open for writing and
// control: the null and zero devices, the controlling terminal, and the
// device the JavaScript and Python runtimes open for their probes. Another
// terminal of the same user is not among them.
var seatbeltDevices = []string{"/dev/dtracehelper", "/dev/null", "/dev/tty", "/dev/zero"}

// RenderSeatbelt turns a profile into the Seatbelt profile sandbox-exec runs
// a stage under, with the same path policy Render gives srt.
//
// Everything is denied unless a rule allows it, and where rules overlap the
// last one that matches decides, so the rules are written from the broadest
// to the narrowest. Reads are allowed everywhere, then the home directory is
// denied, then the profile's reads are allowed back, then the always-deny
// table and the profile's denials are denied again, so a denial wins inside
// any grant. The directories above a grant inside the home directory may be
// examined but not listed, so a program can resolve the grant's path. Writes
// are allowed only in the profile's writes, then DenyWrites and every denied
// read are denied inside them.
//
// proxyPort is the loopback port of the stage's egress proxy, the one
// network destination the stage may reach. Zero renders no network at all:
// no connection, no name lookup and no local socket.
//
// Seatbelt matches the resolved path a process opens, so every path is
// written both as given and with its symbolic links resolved. A path holding
// a control character is refused, because the profile language has no safe
// way to write it.
func RenderSeatbelt(profile Profile, proxyPort int) (string, error) {
	var homes []string
	if profile.Home != "" {
		homes = canonicalAll([]string{profile.Home})
	}
	denyRead := canonicalAll(expandAll(profile.Home, append(append([]string(nil), AlwaysDenyRead...), profile.Denies...)))
	reads := canonicalAll(profile.Reads)
	writes := canonicalAll(profile.Writes)
	denyWrites := canonicalAll(append(append([]string(nil), profile.DenyWrites...), denyRead...))
	var ancestors []string
	for _, home := range homes {
		ancestors = append(ancestors, home)
		for _, path := range append(append([]string(nil), reads...), writes...) {
			ancestors = append(ancestors, above(home, path)...)
		}
	}
	for _, path := range concat(homes, denyRead, reads, writes, denyWrites) {
		if strings.ContainsFunc(path, isControl) {
			return "", fmt.Errorf("render seatbelt profile: the path %q holds a control character", path)
		}
	}

	var b strings.Builder
	b.WriteString(";; A stage's Seatbelt profile, rendered by latere.ai/x/pkg/hostsandbox.\n")
	b.WriteString(";; Where rules overlap, the last one that matches decides.\n")
	b.WriteString("(version 1)\n(deny default)\n")
	b.WriteString("(allow process-exec)\n(allow process-fork)\n")
	b.WriteString("(allow signal (target same-sandbox))\n(allow process-info* (target same-sandbox))\n")
	b.WriteString("(allow sysctl-read)\n(allow file-map-executable)\n")
	b.WriteString("(allow ipc-posix-sem)\n(allow ipc-posix-shm)\n(allow user-preference-read)\n")
	rule(&b, "allow", "mach-lookup", "global-name", seatbeltServices)

	b.WriteString(";; Reads: everywhere but the home directory, then the grants, then the denials.\n")
	b.WriteString("(allow file-read*)\n")
	rule(&b, "deny", "file-read*", "subpath", homes)
	rule(&b, "allow", "file-read-metadata", "literal", sorted(ancestors))
	rule(&b, "allow", "file-read*", "subpath", reads)
	rule(&b, "deny", "file-read*", "subpath", denyRead)

	b.WriteString(";; Writes: only the grants, less what stays read-only inside them.\n")
	rule(&b, "allow", "file-write*", "subpath", writes)
	rule(&b, "deny", "file-write*", "subpath", denyWrites)
	rule(&b, "allow", "file-write*", "literal", seatbeltDevices)
	rule(&b, "allow", "file-ioctl", "literal", seatbeltDevices)

	if proxyPort > 0 {
		b.WriteString(";; Network: the stage's egress proxy on the loopback interface, and nothing else.\n")
		fmt.Fprintf(&b, "(allow network-outbound (remote ip %s))\n", sbString("localhost:"+strconv.Itoa(proxyPort)))
	}
	return b.String(), nil
}

// rule writes one rule naming every value as a filter, or nothing when there
// are no values: a rule with no filter would apply to every path.
func rule(b *strings.Builder, action, operation, filter string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "(%s %s", action, operation)
	for _, value := range values {
		fmt.Fprintf(b, "\n  (%s %s)", filter, sbString(value))
	}
	b.WriteString(")\n")
}

// sbString writes a value as a string of the profile language: in double
// quotes, with a backslash and a double quote escaped.
func sbString(value string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// evalSymlinks resolves a path's symbolic links. A test replaces it.
var evalSymlinks = filepath.EvalSymlinks

// canonical returns a path as written and, when it differs, with its
// symbolic links resolved: /tmp/x is also /private/tmp/x. A path that does
// not exist yet is resolved through its deepest existing ancestor, so a
// grant made before its directory is created still matches once it is.
func canonical(path string) []string {
	clean := filepath.Clean(path)
	out := []string{clean}
	dir, rest := clean, ""
	for {
		if real, err := evalSymlinks(dir); err == nil {
			if resolved := filepath.Join(real, rest); resolved != clean {
				out = append(out, resolved)
			}
			return out
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return out
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
}

// canonicalAll is canonical over every path, trimmed, without empties or
// duplicates, and sorted, so two equal profiles render the same text.
func canonicalAll(paths []string) []string {
	var out []string
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			continue
		}
		out = append(out, canonical(strings.TrimSpace(path))...)
	}
	return sorted(out)
}

// above lists the directories between home and path, from path's parent up
// to the directory just below home, for a path inside home; nothing for a
// path outside it. Home itself is examinable separately.
func above(home, path string) []string {
	if !strings.HasPrefix(path, home+string(filepath.Separator)) {
		return nil
	}
	var out []string
	for dir := filepath.Dir(path); dir != home && strings.HasPrefix(dir, home); dir = filepath.Dir(dir) {
		out = append(out, dir)
	}
	return out
}

func concat(lists ...[]string) []string {
	var out []string
	for _, list := range lists {
		out = append(out, list...)
	}
	return out
}
