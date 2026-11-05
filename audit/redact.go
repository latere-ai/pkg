// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"regexp"
)

// Redact scrubs credential-shaped substrings out of free-form text. Patterns
// covered: bearer tokens in Authorization headers, shell-style *_KEY= /
// *_SECRET= / *_TOKEN= / *_PASSWORD= assignments, basic-auth-in-URL, JWTs,
// AWS access keys, GitHub classic + fine-grained + installation + user +
// refresh tokens, and OpenAI / Anthropic long keys. Each match is replaced
// with "***".
//
// RedactJSON walks a JSON value and calls Redact on every string leaf, and
// blanks the value of any field whose key ends in
// key/secret/token/password/credential (singular or plural).
func Redact(s string) string {
	if s == "" {
		return s
	}
	out := s
	for _, r := range rules {
		out = r.re.ReplaceAllString(out, r.replacement)
	}
	return out
}

// RedactJSON walks the given JSON value and scrubs credential-shaped strings.
// Returns the re-marshaled JSON. On parse failure it returns the input
// passed through Redact (whole-string scrub) so callers can use it on
// arbitrary blobs.
func RedactJSON(b []byte) []byte {
	// Numbers stay as the digits they arrived with, so integers above 2^53
	// (snowflake IDs, unix-ns timestamps) are not mangled by a float64
	// round-trip.
	dec := jsontext.NewDecoder(bytes.NewReader(b), blobJSON)
	v, err := readTree(dec)
	if err != nil {
		return []byte(Redact(string(b)))
	}
	// Reject trailing data so a blob like `{"a":1}garbage` falls back to the
	// whole-string scrub instead of silently dropping the trailing bytes.
	if _, err := dec.ReadValue(); !errors.Is(err, io.EOF) {
		return []byte(Redact(string(b)))
	}
	cleaned := walk(v)
	out, err := json.Marshal(cleaned, json.Deterministic(true), blobJSON)
	if err != nil {
		return []byte(Redact(string(b)))
	}
	return out
}

// blobJSON admits the blobs this package scrubs: they are process output and
// tool results, so duplicate names and invalid UTF-8 can occur.
var blobJSON = json.JoinOptions(
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
)

// readTree reads one JSON value into maps, slices, strings, bools and nil.
// A number is kept as its raw text in a jsontext.Value.
func readTree(dec *jsontext.Decoder) (any, error) {
	switch dec.PeekKind() {
	case '{':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		m := map[string]any{}
		for dec.PeekKind() != '}' {
			k, err := dec.ReadToken()
			if err != nil {
				return nil, err
			}
			name := k.String() // a token is valid only until the next read
			val, err := readTree(dec)
			if err != nil {
				return nil, err
			}
			m[name] = val
		}
		_, err := dec.ReadToken()
		return m, err
	case '[':
		if _, err := dec.ReadToken(); err != nil {
			return nil, err
		}
		arr := []any{}
		for dec.PeekKind() != ']' {
			e, err := readTree(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, e)
		}
		_, err := dec.ReadToken()
		return arr, err
	case '0':
		raw, err := dec.ReadValue()
		return jsontext.Value(bytes.Clone(raw)), err
	case 0:
		_, err := dec.ReadToken()
		if err == nil {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	default:
		tok, err := dec.ReadToken()
		if err != nil {
			return nil, err
		}
		switch tok.Kind() {
		case '"':
			return tok.String(), nil
		case 't':
			return true, nil
		case 'f':
			return false, nil
		}
		return nil, nil
	}
}

const redacted = "***"

type rule struct {
	re          *regexp.Regexp
	replacement string
}

var rules = []rule{
	{
		regexp.MustCompile(`(?i)(authorization:\s*bearer\s+)[A-Za-z0-9._~+/=-]+`),
		`${1}***`,
	},
	{
		regexp.MustCompile(`(?i)\b(\w*(?:key|secret|token|password|passwd))='[^']*'`),
		`$1='***'`,
	},
	{
		regexp.MustCompile(`(?i)\b(\w*(?:key|secret|token|password|passwd))="[^"]*"`),
		`$1="***"`,
	},
	{
		regexp.MustCompile(`(?i)\b(\w*(?:key|secret|token|password|passwd))=([^\s&'"]+)`),
		`$1=***`,
	},
	{
		regexp.MustCompile(`([a-z][a-z0-9+.-]*://)([^:\s/@]+):([^@\s]+)@`),
		`${1}${2}:***@`,
	},
	{
		regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		`***`,
	},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `***`},
	{regexp.MustCompile(`\bghp_[A-Za-z0-9]{36,}\b`), `***`},
	{regexp.MustCompile(`\bghs_[A-Za-z0-9]{36,}\b`), `***`},
	{regexp.MustCompile(`\bghu_[A-Za-z0-9]{36,}\b`), `***`},
	{regexp.MustCompile(`\bgho_[A-Za-z0-9]{36,}\b`), `***`},
	{regexp.MustCompile(`\bghr_[A-Za-z0-9]{36,}\b`), `***`},
	{regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`), `***`},
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), `***`},
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`), `***`},
}

func walk(v any) any {
	switch t := v.(type) {
	case string:
		return Redact(t)
	case jsontext.Value:
		// A numeric leaf; not a credential string.
		return t
	case map[string]any:
		for k, val := range t {
			if looksLikeCredentialKey(k) {
				t[k] = redacted
				continue
			}
			t[k] = walk(val)
		}
		return t
	case []any:
		for i, e := range t {
			t[i] = walk(e)
		}
		return t
	default:
		return v
	}
}

// credentialKeyRe matches JSON keys whose values are credentials. The optional
// trailing "s" catches plural field names (keys/tokens/secrets/...), which carry
// credentials as often as the singular form. The "$" anchor keeps
// "authorization"/"auth" scoped to real auth fields (and to "oauth"-style
// suffixes) without blanking a benign "author"/"authors" field (the trailing
// "or" defeats the anchor).
var credentialKeyRe = regexp.MustCompile(`(?i)(key|secret|token|password|passwd|credential|authorization|auth)s?$`)

func looksLikeCredentialKey(k string) bool {
	return credentialKeyRe.MatchString(k)
}
