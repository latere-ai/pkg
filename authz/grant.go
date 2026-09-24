// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"encoding/json"
	"fmt"
	"slices"

	"latere.ai/x/pkg/authkit"
)

// The grants a credential carries, applied at a decision point.
//
// A personal access token is the person who holds it. A grant is what the
// person said that credential may do instead: one action of a published
// [Vocabulary], paired with a resource selector. The set travels on the
// token as RFC 9396's "authorization_details" and reaches a decision
// point in [Request.Claims], which a PEP forwards verbatim.
//
// The rule is one conjunction:
//
//	allow(req) = decide(req) AND ( token_use(req) != pat
//	                               OR EXISTS g in G(req) : covers(g, req) )
//
//	covers(g, req) = qualified(req.action) in g.actions
//	                 AND ( g.identifier = "" OR g.identifier = req.resource.id )
//
// Three properties follow, and each is a test.
//
//  1. The role is the ceiling. The intersection is a conjunction, so it
//     turns an allow into a deny and never a deny into an allow. A PAT
//     never exceeds the person.
//  2. A grant is not authority. A grant on a resource the person cannot
//     reach still reaches nothing: decide answers first.
//  3. A denial is decidable without the control plane's tables. If no
//     grant covers the request the answer is a deny whatever decide would
//     have said, which is what makes the conformance case writable by a
//     suite that knows nothing about who owns what.
//
// The kind is not compared. An action names exactly one kind in its
// vocabulary ([NewVocabulary] refuses a name that appears twice) and the
// entry was validated against that kind where the key was created, so
// comparing it again here would only fail an entry creation already
// refused.

// Grant is one RFC 9396 authorization_details entry, [authkit.Grant]: an
// action set paired with a resource selector. It is declared once, in the
// package that owns [authkit.Identity], so the shape a token is verified
// against and the shape a decision applies cannot drift.
type Grant = authkit.Grant

// Grants is the whole set a token carries, [authkit.Grants].
type Grants = authkit.Grants

// GrantType is the one authorization_details type of the family,
// "latere-authz". An entry of another type is another party's and covers
// nothing here.
const GrantType = authkit.GrantType

// TokenUsePAT is a "token_use" claim value grants narrow,
// [authkit.TokenUsePAT]: a token minted from a personal access token. A
// request whose claims carry a value [authkit.NarrowedByGrants] does not
// name is decided by the decision point alone.
const TokenUsePAT = authkit.TokenUsePAT

// TokenUseServiceAccountKey is the "token_use" claim value of a token
// minted from a service account's key, [authkit.TokenUseServiceAccountKey].
// Grants narrow it as they narrow [TokenUsePAT].
const TokenUseServiceAccountKey = authkit.TokenUseServiceAccountKey

// ReasonGrant is the deny a decision point writes when the caller's token
// carries grants and none of them covers the request. It is the answer
// that needs none of the control plane's tables: the credential says what
// it may do, and this is not it.
const ReasonGrant = "grant"

// ParseGrants reads the grants off a verified envelope. A request whose
// "token_use" [authkit.NarrowedByGrants] does not name carries none,
// whatever the claim says, because no other credential class is narrowed
// this way.
//
// An envelope with no claims, and one whose claim is absent, carry no
// grant and no error: what that answers is [Restrict]'s. A claim that
// cannot be read as grants is an error, so a decision point decides
// nothing from a claim nobody could parse.
func ParseGrants(claims map[string]any) (Grants, error) {
	use, _ := claims["token_use"].(string)
	if !authkit.NarrowedByGrants(use) {
		return nil, nil
	}
	raw, ok := claims["authorization_details"]
	if !ok || raw == nil {
		return nil, nil
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: authorization_details: %w", authkit.ErrMalformedGrants, err)
	}
	return authkit.ParseGrants(b)
}

// Restrict is the conjunction: it turns an allow into a deny when the
// caller's token carries grants and none of them covers the request, and
// it never turns a deny into an allow.
//
// core qualifies the request's bare action, and it is the [Vocabulary.Core]
// of the decision point applying the rule. The claim carries
// "origo:repo.read" and the envelope carries "repo.read", so a comparison
// that forgets to qualify denies everything; the core is a parameter and
// not an inference.
//
// A token whose "token_use" [authkit.NarrowedByGrants] does not name is
// decided by d alone. A key-minted token that carries no grant at all is
// denied: an absent claim is not full access, and neither is an empty
// array. auth refuses an empty array where a key is created and writes a
// grant list onto every key that predates this, so a live key always
// carries one, and a token carrying none is a token nobody wrote a grant
// for.
func Restrict(core string, d Decision, req Request, grants Grants) Decision {
	if !d.Allow {
		return d
	}
	if use, _ := req.Claims["token_use"].(string); !authkit.NarrowedByGrants(use) {
		return d
	}
	if slices.ContainsFunc(grants, func(g Grant) bool { return covers(core, g, req) }) {
		return d
	}
	// The deny carries the reason and nothing the allow had: a ttl, a
	// limits object and a filter are all statements about an answer that
	// is no longer being given.
	return Decision{Reason: ReasonGrant}
}

// covers reports whether one grant covers one request: the entry is this
// family's, it names the request's action qualified by the core, and its
// selector is either every resource of the kind or exactly this one.
//
// An action that names no object, a list and every create, carries a
// resource with a kind and no id. It is covered by the kind-wide selector
// and by no single-resource selector, which is the right answer: a grant
// on one repository is not a grant to list the directory.
func covers(core string, g Grant, req Request) bool {
	if g.Type != GrantType {
		return false
	}
	if !slices.Contains(g.Actions, core+":"+req.Action) {
		return false
	}
	return g.Identifier == "" || g.Identifier == req.Resource.ID
}
