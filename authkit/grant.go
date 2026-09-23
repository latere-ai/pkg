// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authkit

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// A grant narrows one credential. A personal access token is the person
// who holds it (identity id-12), so a key pasted into a job to read one
// repository reaches everything else that person reaches; the grants are
// what the person says the key may do instead, chosen when the key is
// created and carried on every token it mints.
//
// They travel as "authorization_details", the RFC 9396 claim, with the
// fields that RFC defines and no extension field. This package reads the
// claim; what a grant means is decided at a decision point, by
// latere.ai/x/pkg/authz.

// TokenUsePAT is the "token_use" of a token minted from a personal access
// token (identity id-12, R2), in the personal context or, as a member key,
// in an organization's.
const TokenUsePAT = "pat"

// TokenUseServiceAccountKey is the "token_use" of a token minted from a
// service account's key. The key carries grants as a personal access token
// does, so its token is narrowed by them.
const TokenUseServiceAccountKey = "sak"

// NarrowedByGrants reports whether a token of this "token_use" is narrowed
// by its grants: the classes minted from a stored key, [TokenUsePAT] and
// [TokenUseServiceAccountKey]. A token of any other class is decided by the
// decision point alone, whatever the claim carries.
func NarrowedByGrants(tokenUse string) bool {
	return tokenUse == TokenUsePAT || tokenUse == TokenUseServiceAccountKey
}

// GrantType is the one authorization_details type of the family. RFC 9396
// leaves the fields of an entry to its type, and this is the type that
// fixes them to the table on [Grant]. An entry of another type is not this
// family's and is refused rather than read.
const GrantType = "latere-authz"

// Grant is one RFC 9396 authorization_details entry: an action set paired
// with a resource selector.
//
//	Field        Carries
//	─────        ───────
//	type         GrantType, which fixes the fields below
//	actions      qualified action names, "origo:repo.read"
//	datatypes    one resource kind, ["Repository"]
//	locations    the resource server the entry is for
//	identifier   one resource id; absent is every resource of the kind
//
// An entry is one selector, so a key that grants read on two repositories
// carries two entries and the array is the set.
type Grant struct {
	Type       string   `json:"type"`
	Actions    []string `json:"actions"`
	Datatypes  []string `json:"datatypes,omitempty"`
	Locations  []string `json:"locations,omitempty"`
	Identifier string   `json:"identifier,omitempty"`
}

// Grants is the whole set a token carries: every entry of the claim, in
// the order it was minted in.
type Grants []Grant

// ErrMalformedGrants is a claim that cannot be read as a set of grants.
// The refusal belongs here, at the reader, and not at the decision point:
// a decision about a claim nobody could parse is a decision about nothing.
var ErrMalformedGrants = errors.New("authkit: malformed authorization_details")

// ParseGrants reads the "authorization_details" claim. It refuses what it
// cannot read as this family's grants, each refusal wrapping
// [ErrMalformedGrants]:
//
//   - a claim that is not a JSON array of objects;
//   - an entry whose "type" is not [GrantType], since the type is what
//     fixes the rest of the fields;
//   - an entry that names no action, or names an empty one, which grants
//     nothing and is a claim nobody meant to mint;
//   - an entry whose "datatypes" is more than one kind, since every action
//     of an entry acts on the one kind the selector names.
//
// An empty array is not malformed: it parses to no grant, and a decision
// point then finds nothing that covers the request and denies, which is
// the same answer an absent claim gets. auth refuses an empty array at
// creation, so there is one way to say a thing and this is the reading of
// the other.
func ParseGrants(raw []byte) (Grants, error) {
	var out Grants
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%w: authorization_details is an array of entries: %w", ErrMalformedGrants, err)
	}
	for i, g := range out {
		if g.Type != GrantType {
			return nil, fmt.Errorf("%w: entry %d has type %q; every entry of this family is %q", ErrMalformedGrants, i, g.Type, GrantType)
		}
		if len(g.Actions) == 0 {
			return nil, fmt.Errorf("%w: entry %d names no action", ErrMalformedGrants, i)
		}
		if slices.Contains(g.Actions, "") {
			return nil, fmt.Errorf("%w: entry %d names an empty action", ErrMalformedGrants, i)
		}
		if len(g.Datatypes) > 1 {
			return nil, fmt.Errorf("%w: entry %d names %d datatypes; a selector names one resource kind", ErrMalformedGrants, i, len(g.Datatypes))
		}
	}
	return out, nil
}
