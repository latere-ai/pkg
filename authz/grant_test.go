// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"latere.ai/x/pkg/authkit"
	"latere.ai/x/pkg/authz"
)

const (
	grantedRepo = "7c6b5d4e-3f21-4a90-b8e2-1d0c9b8a7f65"
	otherRepo   = "0f5c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
)

// The three entries infrastructure/identity id-13 writes out, verbatim.
const (
	readOnlyOnOneRepository = `[
  {
    "type": "latere-authz",
    "actions": ["origo:repo.read"],
    "datatypes": ["Repository"],
    "locations": ["https://api.latere.ai"],
    "identifier": "7c6b5d4e-3f21-4a90-b8e2-1d0c9b8a7f65"
  }
]`
	everythingOnEverySandbox = `[
  {
    "type": "latere-authz",
    "actions": [
      "cella:sandbox.create", "cella:sandbox.read",
      "cella:sandbox.update", "cella:sandbox.delete",
      "cella:sandbox.exec", "cella:sandbox.token",
      "cella:sandbox.list"
    ],
    "datatypes": ["Sandbox"],
    "locations": ["https://api.latere.ai"]
  }
]`
	theAdministrativeGroup = `[
  {
    "type": "latere-authz",
    "actions": ["auth:key.read", "auth:key.create", "auth:key.revoke"],
    "datatypes": ["Key"],
    "locations": ["https://auth.latere.ai"]
  }
]`
)

// patClaims is a PAT's verified claims as the envelope carries them: a
// token_use and the grants claim decoded from the token, which is the
// shape a PEP forwards verbatim.
func patClaims(t testing.TB, details string) map[string]any {
	t.Helper()
	claims := map[string]any{"token_use": "pat"}
	if details == "" {
		return claims
	}
	var decoded any
	if err := json.Unmarshal([]byte(details), &decoded); err != nil {
		t.Fatalf("the fixture is not JSON: %v", err)
	}
	claims["authorization_details"] = decoded
	return claims
}

// req is one envelope: who, what, and to which object.
func req(claims map[string]any, action, kind, id string) authz.Request {
	return authz.Request{
		Subject:  "https://auth.latere.ai|ada",
		Issuer:   "https://auth.latere.ai",
		Sub:      "ada",
		Claims:   claims,
		Action:   action,
		Resource: authz.NewResource(kind, id, nil),
	}
}

// allowed is what a decision point answered before the grants narrowed
// it: an allow with every optional field set, so a test can see which of
// them a deny keeps.
var allowed = authz.Decision{Allow: true, TTL: 30 * time.Second,
	Limits: json.RawMessage(`{"requests_per_minute":60}`)}

// TestReasonGrantIsTheWireWord: the word a decision point writes when no
// grant covers the request. It is the reason id-13 names and it replaces
// id-12's rejected "scope".
func TestReasonGrantIsTheWireWord(t *testing.T) {
	if authz.ReasonGrant != "grant" {
		t.Fatalf("ReasonGrant = %q, want %q", authz.ReasonGrant, "grant")
	}
}

// TestParseGrantsReadsTheEnvelope: the claims a PEP forwards verbatim are
// a map, and the grants come off it as the same entries the verifier read
// off the token.
func TestParseGrantsReadsTheEnvelope(t *testing.T) {
	got, err := authz.ParseGrants(patClaims(t, readOnlyOnOneRepository))
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	want := authz.Grants{{
		Type:       authz.GrantType,
		Actions:    []string{"origo:repo.read"},
		Datatypes:  []string{"Repository"},
		Locations:  []string{"https://api.latere.ai"},
		Identifier: grantedRepo,
	}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseGrants =\n%#v\nwant\n%#v", got, want)
	}
}

// verified takes the grants a verifier yields off a token. It is the
// whole of the next test: the call compiles only while authz's type and
// the verifier's are one type.
func verified(g authkit.Grants) int { return len(g) }

// TestParseGrantsIsTheSameTypeTheVerifierReads: one declaration, so the
// shape a token is verified against and the shape a decision applies
// cannot drift, and the wire words are one set of words.
func TestParseGrantsIsTheSameTypeTheVerifierReads(t *testing.T) {
	got, err := authz.ParseGrants(patClaims(t, readOnlyOnOneRepository))
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	if verified(got) != 1 {
		t.Fatalf("a verifier reads %d grants off what a decision point parsed", verified(got))
	}
	if authz.GrantType != authkit.GrantType {
		t.Fatalf("GrantType = %q, want %q", authz.GrantType, authkit.GrantType)
	}
	if authz.TokenUsePAT != authkit.TokenUsePAT {
		t.Fatalf("TokenUsePAT = %q, want %q", authz.TokenUsePAT, authkit.TokenUsePAT)
	}
}

// TestParseGrantsReadsNoneOffANonPAT: no other credential class carries
// the claim, so an envelope whose token_use is not pat carries no grant
// whatever the claim says.
func TestParseGrantsReadsNoneOffANonPAT(t *testing.T) {
	claims := patClaims(t, readOnlyOnOneRepository)
	claims["token_use"] = "session"
	got, err := authz.ParseGrants(claims)
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ParseGrants = %#v, want none", got)
	}
	// An envelope carrying no claims at all is the ordinary case, and it
	// is not an error.
	if got, err := authz.ParseGrants(nil); err != nil || len(got) != 0 {
		t.Fatalf("ParseGrants(nil) = %#v, %v; want none and no error", got, err)
	}
}

// TestParseGrantsRefusesAMalformedClaim: a claim the verifier at a core's
// door would have refused is refused here too, so a decision point that
// is handed one decides nothing from it.
func TestParseGrantsRefusesAMalformedClaim(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim any
	}{
		{"not an array", map[string]any{"type": "latere-authz"}},
		{"another type", []any{map[string]any{"type": "openbanking", "actions": []any{"origo:repo.read"}}}},
		{"no action", []any{map[string]any{"type": "latere-authz"}}},
		// A decision point that deciding locally built its own Request
		// and put something in Claims that never came off a token.
		{"a value no token could carry", func() {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"token_use": "pat", "authorization_details": tc.claim}
			if got, err := authz.ParseGrants(claims); err == nil {
				t.Fatalf("ParseGrants = %#v, want a refusal", got)
			}
		})
	}
}

// TestRestrictNeverWidens is id-13's A8. The intersection is a
// conjunction, so it turns an allow into a deny and never a deny into an
// allow: a PAT never exceeds the person, and a grant on a repository the
// person cannot read still reads nothing.
func TestRestrictNeverWidens(t *testing.T) {
	sets := []string{"", "[]", readOnlyOnOneRepository, everythingOnEverySandbox, theAdministrativeGroup}
	decisions := []authz.Decision{
		{Allow: true},
		allowed,
		{Reason: authz.ReasonNotOwner},
		{Reason: authz.ReasonAnonymous},
	}
	for _, details := range sets {
		grants, err := authz.ParseGrants(patClaims(t, details))
		if err != nil {
			t.Fatalf("ParseGrants: %v", err)
		}
		for _, d := range decisions {
			for _, action := range []string{"repo.read", "repo.write", "repo.list"} {
				for _, id := range []string{grantedRepo, otherRepo, ""} {
					r := req(patClaims(t, details), action, "Repository", id)
					got := authz.Restrict("origo", d, r, grants)
					if got.Allow && !d.Allow {
						t.Fatalf("Restrict turned a deny into an allow: %s on %q under %s", action, id, details)
					}
					if !d.Allow && got.Reason != d.Reason {
						t.Fatalf("Restrict rewrote a deny's reason to %q; the decision point's own reason stands", got.Reason)
					}
				}
			}
		}
	}
}

// TestRestrictCoversTheSpecsExamples: the three entries id-13 writes out,
// each against the requests it covers and the requests it does not. A
// deny carries ReasonGrant, and an allow is the decision point's own
// answer unchanged, limits and ttl included.
func TestRestrictCoversTheSpecsExamples(t *testing.T) {
	for _, tc := range []struct {
		name, core, details string
		action, kind, id    string
		want                bool
	}{
		{"read on the granted repository", "origo", readOnlyOnOneRepository, "repo.read", "Repository", grantedRepo, true},
		{"write on the granted repository", "origo", readOnlyOnOneRepository, "repo.write", "Repository", grantedRepo, false},
		{"read on another repository", "origo", readOnlyOnOneRepository, "repo.read", "Repository", otherRepo, false},
		{"the list of repositories", "origo", readOnlyOnOneRepository, "repo.list", "Repository", "", false},
		{"the same action at another core", "cella", readOnlyOnOneRepository, "repo.read", "Repository", grantedRepo, false},

		{"read on one sandbox", "cella", everythingOnEverySandbox, "sandbox.read", "Sandbox", grantedRepo, true},
		{"read on another sandbox", "cella", everythingOnEverySandbox, "sandbox.read", "Sandbox", otherRepo, true},
		{"the list of sandboxes", "cella", everythingOnEverySandbox, "sandbox.list", "Sandbox", "", true},
		{"a sandbox create", "cella", everythingOnEverySandbox, "sandbox.create", "Sandbox", "", true},
		{"a secret the entry does not name", "cella", everythingOnEverySandbox, "secret.read", "Secret", grantedRepo, false},

		{"an administrative read", "auth", theAdministrativeGroup, "key.read", "Key", grantedRepo, true},
		{"an administrative action the entry omits", "auth", theAdministrativeGroup, "key.rotate", "Key", grantedRepo, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := patClaims(t, tc.details)
			grants, err := authz.ParseGrants(claims)
			if err != nil {
				t.Fatalf("ParseGrants: %v", err)
			}
			got := authz.Restrict(tc.core, allowed, req(claims, tc.action, tc.kind, tc.id), grants)
			if got.Allow != tc.want {
				t.Fatalf("Restrict(%s:%s on %q).Allow = %v, want %v", tc.core, tc.action, tc.id, got.Allow, tc.want)
			}
			if tc.want {
				if !reflect.DeepEqual(got, allowed) {
					t.Fatalf("a covered request answered %#v; the decision point's own answer stands whole", got)
				}
				return
			}
			if got.Reason != authz.ReasonGrant {
				t.Fatalf("reason = %q, want %q", got.Reason, authz.ReasonGrant)
			}
			if got.TTL != 0 || got.Limits != nil || got.Filter != nil {
				t.Fatalf("a deny carried %#v; a refusal carries the reason and nothing the allow had", got)
			}
		})
	}
}

// TestRestrictCoversByIdentifier is id-13's A9. An identifier-less
// selector is every resource of the kind, a list and a create included;
// a selector that names one resource covers that id and nothing else, so
// a grant on one repository is not a grant to list the directory.
func TestRestrictCoversByIdentifier(t *testing.T) {
	wide := authz.Grants{{Type: authz.GrantType, Actions: []string{"origo:repo.read", "origo:repo.list"},
		Datatypes: []string{"Repository"}}}
	one := authz.Grants{{Type: authz.GrantType, Actions: []string{"origo:repo.read", "origo:repo.list"},
		Datatypes: []string{"Repository"}, Identifier: grantedRepo}}
	claims := patClaims(t, "")

	for _, tc := range []struct {
		name       string
		grants     authz.Grants
		action, id string
		want       bool
	}{
		{name: "every resource, one id", grants: wide, action: "repo.read", id: grantedRepo, want: true},
		{name: "every resource, another id", grants: wide, action: "repo.read", id: otherRepo, want: true},
		{name: "every resource, no id", grants: wide, action: "repo.list", id: "", want: true},
		{name: "one resource, that id", grants: one, action: "repo.read", id: grantedRepo, want: true},
		{name: "one resource, another id", grants: one, action: "repo.read", id: otherRepo, want: false},
		{name: "one resource, no id", grants: one, action: "repo.list", id: "", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := authz.Restrict("origo", authz.Decision{Allow: true}, req(claims, tc.action, "Repository", tc.id), tc.grants)
			if got.Allow != tc.want {
				t.Fatalf("Allow = %v, want %v", got.Allow, tc.want)
			}
		})
	}
}

// TestRestrictIgnoresGrantsOnNonPAT is id-13's A10. Grants narrow the
// key-minted classes alone. A session token and an actor token are decided
// by the decision point alone, whatever the claim carries.
func TestRestrictIgnoresGrantsOnNonPAT(t *testing.T) {
	grants, err := authz.ParseGrants(patClaims(t, readOnlyOnOneRepository))
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	for _, use := range []string{"", "session", "actor"} {
		claims := map[string]any{}
		if use != "" {
			claims["token_use"] = use
		}
		// The grants are handed in anyway: what decides is the class.
		got := authz.Restrict("origo", allowed, req(claims, "repo.write", "Repository", otherRepo), grants)
		if !reflect.DeepEqual(got, allowed) {
			t.Fatalf("token_use %q answered %#v; a token that is not a PAT is decided by the decision point alone", use, got)
		}
	}
}

// TestRestrictRefusesAPATWithNoGrants: a PAT that carries no grants
// reaches nothing. An absent claim is not full access and an empty array
// is not either: auth backfills a wildcard grant onto the keys that
// predate this, so a live key always carries a list, and a token with
// none is a token nobody wrote a grant for.
//
// This inverts id-13's A11 (TestRestrictAbsentClaimIsFullAuthority) on
// the maintainer's decision of 2026-09-17.
func TestRestrictRefusesAPATWithNoGrants(t *testing.T) {
	for _, tc := range []struct{ name, details string }{
		{"an absent claim", ""},
		{"an empty array", "[]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := patClaims(t, tc.details)
			grants, err := authz.ParseGrants(claims)
			if err != nil {
				t.Fatalf("ParseGrants: %v", err)
			}
			got := authz.Restrict("origo", allowed, req(claims, "repo.read", "Repository", grantedRepo), grants)
			if got.Allow {
				t.Fatal("a PAT carrying no grant was allowed; no grant covers the request, so the answer is a deny")
			}
			if got.Reason != authz.ReasonGrant {
				t.Fatalf("reason = %q, want %q", got.Reason, authz.ReasonGrant)
			}
		})
	}
}

// TestRestrictReadsTheQualifiedAction: the claim carries core:action and
// the envelope carries the bare action, so the core is what joins them. A
// comparison that forgets to qualify denies everything, which is why the
// core is a parameter and not an inference.
func TestRestrictReadsTheQualifiedAction(t *testing.T) {
	claims := patClaims(t, readOnlyOnOneRepository)
	grants, err := authz.ParseGrants(claims)
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	r := req(claims, "repo.read", "Repository", grantedRepo)
	if got := authz.Restrict("origo", allowed, r, grants); !got.Allow {
		t.Fatal("the entry names origo:repo.read and the request is origo's repo.read; it is covered")
	}
	if got := authz.Restrict("", allowed, r, grants); got.Allow {
		t.Fatal("an unqualified comparison allowed a request; a decision point that names no core covers nothing")
	}
}

// TestRestrictRefusesAnEntryOfAnotherType: RFC 9396 leaves an entry's
// fields to its type, so an entry of another type says nothing about this
// family's actions and covers nothing. It cannot arrive off a verified
// token, which refuses it; this is the decision point holding the same
// line for a claim that reached it another way.
func TestRestrictRefusesAnEntryOfAnotherType(t *testing.T) {
	claims := patClaims(t, "")
	grants := authz.Grants{{Type: "openbanking", Actions: []string{"origo:repo.read"}, Identifier: grantedRepo}}
	if got := authz.Restrict("origo", allowed, req(claims, "repo.read", "Repository", grantedRepo), grants); got.Allow {
		t.Fatal("an entry of another type covered a request")
	}
}

// TestGrantsRenderTheClaim: what a decision point reads is what a minter
// writes, field for field, with no extension field.
func TestGrantsRenderTheClaim(t *testing.T) {
	grants, err := authz.ParseGrants(patClaims(t, readOnlyOnOneRepository))
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	raw, err := json.Marshal(grants)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, field := range []string{`"type"`, `"actions"`, `"datatypes"`, `"locations"`, `"identifier"`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("the rendered entry %s carries no %s", raw, field)
		}
	}
}

// TestRestrictNarrowsAServiceAccountKey: a service account's key carries
// grants as a personal access token does (auth spec 084), so its token is
// narrowed by them and a key-minted token with none is denied.
func TestRestrictNarrowsAServiceAccountKey(t *testing.T) {
	if !authkit.NarrowedByGrants(authz.TokenUseServiceAccountKey) || !authkit.NarrowedByGrants(authz.TokenUsePAT) {
		t.Fatal("NarrowedByGrants must name both key-minted classes")
	}
	for _, use := range []string{"", "session", "actor"} {
		if authkit.NarrowedByGrants(use) {
			t.Fatalf("NarrowedByGrants(%q) = true, want false", use)
		}
	}
	claims := patClaims(t, readOnlyOnOneRepository)
	claims["token_use"] = authz.TokenUseServiceAccountKey
	grants, err := authz.ParseGrants(claims)
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("ParseGrants read no grant off a service account key's token")
	}
	if got := authz.Restrict("origo", allowed, req(claims, "repo.read", "Repository", grantedRepo), grants); !got.Allow {
		t.Fatalf("a covered request was denied: %#v", got)
	}
	got := authz.Restrict("origo", allowed, req(claims, "repo.write", "Repository", otherRepo), grants)
	if got.Allow || got.Reason != authz.ReasonGrant {
		t.Fatalf("an uncovered request answered %#v, want a %q deny", got, authz.ReasonGrant)
	}
	bare := map[string]any{"token_use": authz.TokenUseServiceAccountKey}
	none, err := authz.ParseGrants(bare)
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	if got := authz.Restrict("origo", allowed, req(bare, "repo.read", "Repository", grantedRepo), none); got.Allow {
		t.Fatal("a service account key's token with no grant was allowed")
	}
}
