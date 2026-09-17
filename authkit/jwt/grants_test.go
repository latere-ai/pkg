// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"reflect"
	"testing"

	"latere.ai/x/pkg/authkit"
)

// oneRepositoryRead is the first entry infrastructure/identity id-13
// writes out: read on one repository and nothing else.
func oneRepositoryRead() []any {
	return []any{map[string]any{
		"type":       "latere-authz",
		"actions":    []string{"origo:repo.read"},
		"datatypes":  []string{"Repository"},
		"locations":  []string{"https://api.latere.ai"},
		"identifier": "7c6b5d4e-3f21-4a90-b8e2-1d0c9b8a7f65",
	}}
}

// parsedOneRepositoryRead is the same entry as the reader yields it.
func parsedOneRepositoryRead() authkit.Grants {
	return authkit.Grants{{
		Type:       authkit.GrantType,
		Actions:    []string{"origo:repo.read"},
		Datatypes:  []string{"Repository"},
		Locations:  []string{"https://api.latere.ai"},
		Identifier: "7c6b5d4e-3f21-4a90-b8e2-1d0c9b8a7f65",
	}}
}

// patPayload is a PAT's minted token: the phase 1 claims plus token_use,
// and the grants claim when details is not nil.
func patPayload(details any) map[string]any {
	p := defaultPayload()
	p["token_use"] = authkit.TokenUsePAT
	if details != nil {
		p["authorization_details"] = details
	}
	return p
}

// readsGrants is the promise a core makes about itself: this validator
// reads the claim, so a token that carries one is not refused.
func readsGrants(c *Config) { c.ReadsGrants = true }

// TestValidatorReadsTheGrantsClaim: a validator that reads grants hands
// them back on the identity, beside the token_use that says which
// credential minted the token.
func TestValidatorReadsTheGrantsClaim(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, defaultHeader(key), patPayload(oneRepositoryRead()))

	claims, err := testValidator(t, key, readsGrants).Validate(tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if claims.TokenUse != authkit.TokenUsePAT {
		t.Fatalf("TokenUse = %q, want %q", claims.TokenUse, authkit.TokenUsePAT)
	}
	if want := parsedOneRepositoryRead(); !reflect.DeepEqual(claims.Grants, want) {
		t.Fatalf("Grants =\n%#v\nwant\n%#v", claims.Grants, want)
	}
	// The Identity an Authenticator hands a service carries them too: a
	// service that decides locally reads the grants where it reads the
	// subject, and not from a second place.
	id := claims.authenticated()
	if want := parsedOneRepositoryRead(); !reflect.DeepEqual(id.Grants, want) {
		t.Fatalf("the authenticated Identity carries %#v, want %#v", id.Grants, want)
	}
	if id.TokenUse != authkit.TokenUsePAT {
		t.Fatalf("the authenticated Identity carries token_use %q, want %q", id.TokenUse, authkit.TokenUsePAT)
	}
}

// TestValidatorRefusesUnreadGrants is id-13's A12. A validator that does
// not read grants refuses a PAT token carrying them, because the claim is
// a restriction: a reader that ignores it grants more than the person
// asked for, silently, at the one place nobody is looking.
func TestValidatorRefusesUnreadGrants(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, defaultHeader(key), patPayload(oneRepositoryRead()))

	_, err := testValidator(t, key).Validate(tok)
	if !errors.Is(err, ErrGrantsUnread) {
		t.Fatalf("err = %v, want ErrGrantsUnread", err)
	}
	if got := ReasonOf(err); got != ReasonGrantsUnread {
		t.Fatalf("ReasonOf = %q, want %q", got, ReasonGrantsUnread)
	}
	if _, err := testValidator(t, key, readsGrants).Validate(tok); err != nil {
		t.Fatalf("with ReadsGrants the same token was refused: %v", err)
	}
}

// TestReadsGrantsIsOffByDefault: the flag is a promise a core makes once
// its conformance run passes, so nothing is promised until it is set.
func TestReadsGrantsIsOffByDefault(t *testing.T) {
	if (Config{}).ReadsGrants {
		t.Fatal("ReadsGrants is on in the zero Config; a core promises it, and a default is not a promise")
	}
}

// TestUnreadGrantsIsRefusedAfterTheSignature: a tampered token carrying
// the claim is a bad signature and not an unread grant. The refusal order
// is what keeps the reason honest.
func TestUnreadGrantsIsRefusedAfterTheSignature(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, defaultHeader(key), patPayload(oneRepositoryRead())) + "tampered"

	_, err := testValidator(t, key).Validate(tok)
	if !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("err = %v, want ErrInvalidSignature", err)
	}
}

// TestGrantsAreReadOnlyOnAPAT: no other credential class carries the
// claim, so a token whose token_use is not pat carries no grant whatever
// the claim says, and is not refused by a validator that reads none.
func TestGrantsAreReadOnlyOnAPAT(t *testing.T) {
	key := genKey(t)
	p := defaultPayload()
	p["authorization_details"] = oneRepositoryRead()
	tok := signToken(t, key, defaultHeader(key), p)

	claims, err := testValidator(t, key).Validate(tok)
	if err != nil {
		t.Fatalf("a token that is not a PAT was refused: %v", err)
	}
	if len(claims.Grants) != 0 {
		t.Fatalf("Grants = %#v, want none: the claim is read on a PAT alone", claims.Grants)
	}
	if claims.TokenUse != "" {
		t.Fatalf("TokenUse = %q, want the empty value", claims.TokenUse)
	}
}

// TestAPATWithNoGrantsCarriesNone: an absent claim is no grant. It is not
// full access: what that answers is a decision point's, and it denies.
func TestAPATWithNoGrantsCarriesNone(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, defaultHeader(key), patPayload(nil))

	claims, err := testValidator(t, key).Validate(tok)
	if err != nil {
		t.Fatalf("a PAT token carrying no claim was refused: %v", err)
	}
	if len(claims.Grants) != 0 {
		t.Fatalf("Grants = %#v, want none", claims.Grants)
	}
	if claims.TokenUse != authkit.TokenUsePAT {
		t.Fatalf("TokenUse = %q, want %q", claims.TokenUse, authkit.TokenUsePAT)
	}
	// A claim written as JSON null is an absent claim too, and not a
	// malformed one: there is nothing to read either way.
	p := patPayload(nil)
	p["authorization_details"] = nil
	if _, err := testValidator(t, key).Validate(signToken(t, key, defaultHeader(key), p)); err != nil {
		t.Fatalf("a PAT token whose claim is null was refused: %v", err)
	}
}

// TestValidatorRefusesAMalformedGrantsClaim: a claim that cannot be read
// as grants is a malformed token, the same row org_id's non-string value
// lands in. Both entry paths refuse it, so a token trusted by transport
// cannot carry what a verified token could not.
func TestValidatorRefusesAMalformedGrantsClaim(t *testing.T) {
	key := genKey(t)
	for _, tc := range []struct {
		name    string
		details any
	}{
		{"not an array", map[string]any{"type": "latere-authz"}},
		{"another type", []any{map[string]any{"type": "openbanking", "actions": []string{"origo:repo.read"}}}},
		{"no action", []any{map[string]any{"type": "latere-authz", "actions": []string{}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tok := signToken(t, key, defaultHeader(key), patPayload(tc.details))

			_, err := testValidator(t, key, readsGrants).Validate(tok)
			if !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("Validate: err = %v, want ErrMalformedToken", err)
			}
			if got := ReasonOf(err); got != ReasonMalformed {
				t.Fatalf("ReasonOf = %q, want %q", got, ReasonMalformed)
			}
			if _, err := ParseUnverified(tok); !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("ParseUnverified: err = %v, want ErrMalformedToken", err)
			}
		})
	}
}

// TestParseUnverifiedReadsTheGrantsClaim: a token already trusted by
// transport yields the same grants as a verified one. It reads no Config,
// so ReadsGrants is Validate's alone, as MaxTokenBytes and MaxTokenAge
// are.
func TestParseUnverifiedReadsTheGrantsClaim(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, defaultHeader(key), patPayload(oneRepositoryRead()))

	claims, err := ParseUnverified(tok)
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if want := parsedOneRepositoryRead(); !reflect.DeepEqual(claims.Grants, want) {
		t.Fatalf("Grants =\n%#v\nwant\n%#v", claims.Grants, want)
	}
}
