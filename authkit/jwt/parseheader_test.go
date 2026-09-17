// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"testing"
)

// TestParseHeaderReadsTheJOSEHeader: the three fields a caller picking its
// own key needs, read off a token this package would verify.
func TestParseHeaderReadsTheJOSEHeader(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, defaultHeader(key), defaultPayload())

	h, err := ParseHeader(tok)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h.Alg != "RS256" {
		t.Errorf("Alg = %q, want %q", h.Alg, "RS256")
	}
	if want := rsaKid(&key.PublicKey); h.KID != want {
		t.Errorf("KID = %q, want %q", h.KID, want)
	}
	if h.Typ != "JWT" {
		t.Errorf("Typ = %q, want %q", h.Typ, "JWT")
	}
}

// TestParseHeaderOnAHeaderThatNamesLess: a header carrying only "alg" is
// read, and the fields it does not carry come back empty rather than as a
// refusal. An issuer that publishes one key names no kid.
func TestParseHeaderOnAHeaderThatNamesLess(t *testing.T) {
	key := genKey(t)
	tok := signToken(t, key, map[string]any{"alg": "ES256"}, defaultPayload())

	h, err := ParseHeader(tok)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if h != (Header{Alg: "ES256"}) {
		t.Fatalf("Header = %+v, want the alg alone", h)
	}
}

// TestParseHeaderRefusesWhatIsNotAToken: the three shapes that are not a
// compact JWT header, each ErrMalformedToken. ParseHeader verifies
// nothing, so this is the whole of what it refuses.
func TestParseHeaderRefusesWhatIsNotAToken(t *testing.T) {
	for _, tc := range []struct{ name, token string }{
		{"not three segments", "one.two"},
		{"a header that is not base64url", "!!!.payload.sig"},
		{"a header that is not JSON", b64("a string, not an object") + ".payload.sig"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := ParseHeader(tc.token)
			if !errors.Is(err, ErrMalformedToken) {
				t.Fatalf("err = %v, want ErrMalformedToken", err)
			}
			if h != (Header{}) {
				t.Fatalf("Header = %+v, want the zero header", h)
			}
		})
	}
}
