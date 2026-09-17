// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"latere.ai/x/pkg/authkit"
)

// readOnlyOnOneRepository is the first of the three entries
// infrastructure/identity/id-13-pat-scopes.md writes out, verbatim.
const readOnlyOnOneRepository = `[
  {
    "type": "latere-authz",
    "actions": ["origo:repo.read"],
    "datatypes": ["Repository"],
    "locations": ["https://api.latere.ai"],
    "identifier": "7c6b5d4e-3f21-4a90-b8e2-1d0c9b8a7f65"
  }
]`

// everythingOnEverySandbox is the second: a kind-wide entry, which carries
// no identifier at all.
const everythingOnEverySandbox = `[
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

// theAdministrativeGroup is the third: the shape of the group id-13 defines
// and does not issue. It parses like any other entry; what keeps it out of
// a token is auth's creation rule and the audience a PAT may name, neither
// of which is a reader's business.
const theAdministrativeGroup = `[
  {
    "type": "latere-authz",
    "actions": ["auth:key.read", "auth:key.create", "auth:key.revoke"],
    "datatypes": ["Key"],
    "locations": ["https://auth.latere.ai"]
  }
]`

// TestParseGrantsReadsTheSpecsExamples: the three entries id-13 writes out
// parse into the fields the RFC 9396 table names, and nothing is dropped.
func TestParseGrantsReadsTheSpecsExamples(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want authkit.Grants
	}{
		{
			name: "read only on one repository",
			raw:  readOnlyOnOneRepository,
			want: authkit.Grants{{
				Type:       authkit.GrantType,
				Actions:    []string{"origo:repo.read"},
				Datatypes:  []string{"Repository"},
				Locations:  []string{"https://api.latere.ai"},
				Identifier: "7c6b5d4e-3f21-4a90-b8e2-1d0c9b8a7f65",
			}},
		},
		{
			name: "everything on every sandbox",
			raw:  everythingOnEverySandbox,
			want: authkit.Grants{{
				Type: authkit.GrantType,
				Actions: []string{
					"cella:sandbox.create", "cella:sandbox.read",
					"cella:sandbox.update", "cella:sandbox.delete",
					"cella:sandbox.exec", "cella:sandbox.token",
					"cella:sandbox.list",
				},
				Datatypes: []string{"Sandbox"},
				Locations: []string{"https://api.latere.ai"},
			}},
		},
		{
			name: "the administrative group",
			raw:  theAdministrativeGroup,
			want: authkit.Grants{{
				Type:      authkit.GrantType,
				Actions:   []string{"auth:key.read", "auth:key.create", "auth:key.revoke"},
				Datatypes: []string{"Key"},
				Locations: []string{"https://auth.latere.ai"},
			}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authkit.ParseGrants([]byte(tc.raw))
			if err != nil {
				t.Fatalf("ParseGrants: %v", err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("ParseGrants =\n%#v\nwant\n%#v", got, tc.want)
			}
		})
	}
}

// TestGrantTypeIsTheOneTypeOfTheFamily: the discriminator is the string the
// wire table fixes, and it is what tells an entry of this family from
// another authorization_details type on the same claim.
func TestGrantTypeIsTheOneTypeOfTheFamily(t *testing.T) {
	if authkit.GrantType != "latere-authz" {
		t.Fatalf("GrantType = %q, want %q", authkit.GrantType, "latere-authz")
	}
}

// TestParseGrantsRefusesAMalformedClaim: the reader refuses what it cannot
// read as a set of grants. Each row is a claim a token could carry and a
// decision point must never see, so the refusal is here and not at the
// decision.
func TestParseGrantsRefusesAMalformedClaim(t *testing.T) {
	for _, tc := range []struct {
		name, raw, says string
	}{
		{"not JSON", "{not json", "authorization_details"},
		{"not an array", `{"type":"latere-authz"}`, "authorization_details"},
		{"an entry that is not an object", `["origo:repo.read"]`, "authorization_details"},
		{"another type", `[{"type":"openbanking","actions":["origo:repo.read"]}]`, "latere-authz"},
		{"no type", `[{"actions":["origo:repo.read"]}]`, "latere-authz"},
		{"no action", `[{"type":"latere-authz","actions":[]}]`, "action"},
		{"an empty action", `[{"type":"latere-authz","actions":[""]}]`, "action"},
		{"two datatypes", `[{"type":"latere-authz","actions":["origo:repo.read"],"datatypes":["Repository","Key"]}]`, "kind"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := authkit.ParseGrants([]byte(tc.raw))
			if err == nil {
				t.Fatalf("ParseGrants(%s) = %#v, want a refusal", tc.raw, got)
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Fatalf("ParseGrants(%s) = %v, want a message naming %q", tc.raw, err, tc.says)
			}
		})
	}
}

// TestParseGrantsReadsAnEmptyArray: an empty array is not malformed. auth
// refuses it at creation, and a decision point that is handed one anyway
// finds no grant that covers the request and denies, which is the same
// answer as an absent claim.
func TestParseGrantsReadsAnEmptyArray(t *testing.T) {
	got, err := authkit.ParseGrants([]byte(`[]`))
	if err != nil {
		t.Fatalf("ParseGrants([]): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("ParseGrants([]) = %#v, want no grant", got)
	}
}

// TestGrantsRoundTripTheClaim: the entry is rendered with the RFC 9396
// field names and no extension field, so what a reader parses is what a
// minter writes.
func TestGrantsRoundTripTheClaim(t *testing.T) {
	want, err := authkit.ParseGrants([]byte(readOnlyOnOneRepository))
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := authkit.ParseGrants(raw)
	if err != nil {
		t.Fatalf("ParseGrants(rendered): %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round trip =\n%#v\nwant\n%#v", got, want)
	}
	// The kind-wide entry omits the identifier rather than writing it
	// empty: absent is how "every resource of the kind" is said.
	wide, err := authkit.ParseGrants([]byte(everythingOnEverySandbox))
	if err != nil {
		t.Fatalf("ParseGrants: %v", err)
	}
	rendered, err := json.Marshal(wide)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(rendered), "identifier") {
		t.Fatalf("a kind-wide entry rendered %s; the identifier is omitted, not empty", rendered)
	}
}

// TestTokenUsePAT: the claim value that says a token was minted from a
// personal access token (id-12 R2). It is the one credential class the
// grants narrow.
func TestTokenUsePAT(t *testing.T) {
	if authkit.TokenUsePAT != "pat" {
		t.Fatalf("TokenUsePAT = %q, want %q", authkit.TokenUsePAT, "pat")
	}
}
