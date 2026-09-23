// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The identity work left this package one sentence of guidance: no
// service imports anything from authkit/oidc except Provider and the
// session handlers. The three lists below are that sentence applied to
// the surface this package actually has, so a name added to it is a
// decision somebody made rather than one that happened.
//
// Nothing here is deleted by this test and nothing is forbidden by it.
// What it does is make the surface visible: a new export fails the test
// until it is written down and placed in one of the three groups, which
// is the moment to ask whether a service should be reaching for it.

// providerSurface is the relying party for any standard OIDC issuer —
// Latere auth, Keycloak, Google, Cognito — and the claim mapping it is
// built from. It is the first half of what the epic's sentence allows.
//
// User is listed here because a ClaimsMapper produces one and
// Provider.VerifyIDToken returns one; the session half returns it too,
// from Client.UserFromRequest, so it is the one type both halves share.
var providerSurface = []string{
	"func NewProvider",
	"type ClaimsMapper",
	"type CognitoMapper",
	"type GoogleMapper",
	"type KeycloakMapper",
	"type LatereMapper",
	"type Provider",
	"type ProviderConfig",
	"type User",
}

// sessionHandlers is the second half: the Latere relying party that keeps
// a person signed in through an encrypted cookie, and everything a
// service needs to serve that flow. It is what the epic's sentence means
// by "the session handlers", named here rather than left to a reader to
// guess:
//
//   - the client and its configuration — Client, New, Config, LoadConfig,
//     LoadConfigWithPrefix;
//   - the session itself — Session, SessionFromToken, ErrSessionExpired,
//     SessionCookieName, SessionMaxAge, ClearSession, and
//     ErrSwitchOrgRefused, the refusal of Client.SwitchOrg, which moves a
//     session into another context;
//   - the authorization-code flow's short-lived state — FlowState,
//     FlowCookieName, FlowMaxAge, ClearFlowState, GenerateState,
//     GenerateVerifier;
//   - the authenticator that turns a cookie into an authkit.Identity —
//     SessionAuthenticator, NewSessionAuthenticator;
//   - the shared /me assembly a console renders — Me, OrgEntry, Initials,
//     SwitchOrgRedirect.
//
// The handlers themselves are methods on Client (HandleLogin,
// HandleCallback, HandleLogout, HandleLogoutNotify, SessionFromRequest,
// UserFromRequest, BuildMe), so they are reached through the type and are
// not package-level names.
var sessionHandlers = []string{
	"const FlowCookieName",
	"const FlowMaxAge",
	"const SessionCookieName",
	"const SessionMaxAge",
	"func ClearFlowState",
	"func ClearSession",
	"func GenerateState",
	"func GenerateVerifier",
	"func Initials",
	"func LoadConfig",
	"func LoadConfigWithPrefix",
	"func New",
	"func NewSessionAuthenticator",
	"func SessionFromToken",
	"func SwitchOrgRedirect",
	"type Client",
	"type Config",
	"type FlowState",
	"type Me",
	"type OrgEntry",
	"type Session",
	"type SessionAuthenticator",
	"var ErrSessionExpired",
	"var ErrSwitchOrgRefused",
}

// outsideTheAllowance is exported and is neither Provider nor a session
// handler: the machine-to-machine minting this package grew beside the
// browser flow. A service reaching for one of these is reaching past the
// epic's sentence, which may be right and is at least worth knowing.
//
//   - ClientCredentials, ServiceTokenSource, NewServiceTokenSource and
//     ServiceTokenLifetimeMargin mint and refresh a service's own token;
//   - MintActorToken and ActorTokenLifetime mint the short-lived token a
//     console exchanges a person's session for.
var outsideTheAllowance = []string{
	"const ActorTokenLifetime",
	"const ServiceTokenLifetimeMargin",
	"func ClientCredentials",
	"func MintActorToken",
	"func NewServiceTokenSource",
	"type ServiceTokenSource",
}

// TestTheExportedSurfaceIsPinned reads this package's own source and
// holds its package-level exports to the three lists above. A name in the
// source and in no list, or in a list and not in the source, fails.
func TestTheExportedSurfaceIsPinned(t *testing.T) {
	pinned := slices.Concat(providerSurface, sessionHandlers, outsideTheAllowance)
	slices.Sort(pinned)
	if i := firstDuplicate(pinned); i != "" {
		t.Fatalf("%q is pinned in more than one group; a name belongs to one", i)
	}

	got := exportedNames(t, ".")
	if len(got) == 0 {
		t.Fatal("the walk read no exported name; it is not reading this package")
	}

	added := missing(got, pinned)
	removed := missing(pinned, got)
	if len(added) > 0 {
		t.Errorf("authkit/oidc exports names no list carries:\n\t%s\n"+
			"An export here is a thing a service can reach for. Put each in providerSurface, "+
			"sessionHandlers or outsideTheAllowance, and say in the comment which it is.",
			strings.Join(added, "\n\t"))
	}
	if len(removed) > 0 {
		t.Errorf("these names are pinned and no longer exported:\n\t%s\n"+
			"Drop them from the list in the same change that removes them.",
			strings.Join(removed, "\n\t"))
	}
}

// exportedNames is every package-level exported identifier declared in
// dir's non-test Go files, rendered as "kind Name" and sorted. Methods
// are not listed: they are reached through their type, which is listed.
func exportedNames(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		out = append(out, exportedIn(f)...)
	}
	slices.Sort(out)
	return out
}

// exportedIn is one file's package-level exported declarations.
func exportedIn(f *ast.File) []string {
	var out []string
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			if d.Recv == nil && d.Name.IsExported() {
				out = append(out, "func "+d.Name.Name)
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.IsExported() {
						out = append(out, "type "+s.Name.Name)
					}
				case *ast.ValueSpec:
					for _, n := range s.Names {
						if n.IsExported() {
							out = append(out, d.Tok.String()+" "+n.Name)
						}
					}
				}
			}
		}
	}
	return out
}

// missing is every entry of a that b does not carry.
func missing(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	return out
}

// firstDuplicate is the first entry a sorted list carries twice, or "".
func firstDuplicate(sorted []string) string {
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			return sorted[i]
		}
	}
	return ""
}
