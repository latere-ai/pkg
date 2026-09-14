// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package jwt

import (
	"errors"
	"testing"

	"latere.ai/x/pkg/authkit/issuertest"
)

// familyValidator is the verifier configured the way a core runs it:
// the issuer's JWKS, the issuer, one audience.
func familyValidator(iss *issuertest.Server) *Validator {
	return New(Config{JWKSURL: iss.JWKSURL(), Issuer: iss.URL(), Audiences: []string{"core"}})
}

// TestValidateES256BesideRS256 is the shared verifier's C5 (latere-ai/specs
// infrastructure/open-cores.md): a token signed ES256 over a P-256 key
// served as kty EC verifies, and an RS256 one still does.
func TestValidateES256BesideRS256(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []issuertest.Option
	}{
		{"ES256", []issuertest.Option{issuertest.WithES256()}},
		{"RS256", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iss := issuertest.New(t, tc.opts...)
			tok := iss.Mint(issuertest.Claims{Sub: "alice", Aud: issuertest.StringList{"core"}, OrgID: "org1"})
			c, err := familyValidator(iss).Validate(tok)
			if err != nil {
				t.Fatalf("an %s token was refused: %v", tc.name, err)
			}
			if c.Sub != "alice" || c.OrgID != "org1" || c.Iss != iss.URL() {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
}

// TestValidateRefusesAMismatchedAlgAndKey: the header's alg selects the
// key family, so a signature is never checked against a key of the other
// kind, whatever the header claims.
func TestValidateRefusesAMismatchedAlgAndKey(t *testing.T) {
	ec := issuertest.New(t, issuertest.WithES256())
	rs := issuertest.New(t)
	aud := issuertest.StringList{"core"}
	for _, tc := range []struct {
		name  string
		iss   *issuertest.Server
		token string
	}{
		// Signed by the P-256 key, header says RS256: the set holds no RSA key.
		{"an EC signature under an RS256 header", ec, ec.Mint(issuertest.Claims{Aud: aud, Alg: "RS256"})},
		// Signed by the RSA key, header says ES256: the set holds no EC key.
		{"an RSA signature under an ES256 header", rs, rs.Mint(issuertest.Claims{Aud: aud, Alg: "ES256"})},
		// A genuine ES256 token presented to an issuer that serves RSA keys.
		{"an ES256 token against an RSA key set", rs, ec.Mint(issuertest.Claims{Aud: aud})},
		// A genuine RS256 token presented to an issuer that serves EC keys.
		{"an RS256 token against an EC key set", ec, rs.Mint(issuertest.Claims{Aud: aud})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := familyValidator(tc.iss).Validate(tc.token)
			if !errors.Is(err, ErrInvalidSignature) {
				t.Fatalf("err = %v, want ErrInvalidSignature", err)
			}
		})
	}
	// An algorithm that is neither is unsupported before any key is read.
	_, err := familyValidator(ec).Validate(ec.Mint(issuertest.Claims{Aud: aud, Alg: "ES384"}))
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("ES384: err = %v, want ErrUnsupportedAlg", err)
	}
}

// TestValidateES256SignatureLength: the JWS form of an ES256 signature is
// exactly r and s, 64 bytes; any other length is not a signature.
func TestValidateES256SignatureLength(t *testing.T) {
	iss := issuertest.New(t, issuertest.WithES256())
	tok := iss.Mint(issuertest.Claims{Aud: issuertest.StringList{"core"}})
	short := tok[:len(tok)-4]
	if _, err := familyValidator(iss).Validate(short); !errors.Is(err, ErrInvalidSignature) {
		t.Fatalf("truncated signature: err = %v, want ErrInvalidSignature", err)
	}
}
