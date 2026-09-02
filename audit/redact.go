// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"encoding/json"
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
	var v any
	// UseNumber so integers above 2^53 (snowflake IDs, unix-ns timestamps)
	// survive as json.Number instead of being mangled by a float64 round-trip.
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return []byte(Redact(string(b)))
	}
	// Reject trailing data so a blob like `{"a":1}garbage` falls back to the
	// whole-string scrub instead of silently dropping the trailing bytes
	// (json.Unmarshal rejected this; the streaming decoder does not).
	if dec.More() {
		return []byte(Redact(string(b)))
	}
	cleaned := walk(v)
	out, err := json.Marshal(cleaned)
	if err != nil {
		return []byte(Redact(string(b)))
	}
	return out
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
	case json.Number:
		// A numeric leaf (from UseNumber); not a credential string.
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
