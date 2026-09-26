// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import "strings"

// PrefersMarkdown reports whether an Accept header value ranks text/markdown
// strictly above text/html.
//
// Each media type's quality comes from the most specific range that matches
// it, as RFC 9110 section 12.5.1 orders them: the exact type, then "text/*",
// then "*/*". A type no range matches has quality zero. A tie goes to HTML,
// because HTML is the page's primary representation: a browser's
// "text/html,...,*/*;q=0.8" and a bare "*/*" both keep HTML, while
// "text/markdown" alone or "text/markdown, text/html;q=0.9" selects
// Markdown.
//
// Media-type parameters other than q are ignored, so
// "text/markdown;charset=utf-8" matches. An element that does not parse, or
// whose q is not a valid qvalue, is skipped rather than read as q=1. Pass the
// header's values joined with commas when a request carries it more than
// once.
func PrefersMarkdown(accept string) bool {
	md, html := acceptQuality(accept)
	return md > html
}

// Specificity of a media range against one media type, ranked so a larger
// value is more specific. matchNone means the range does not cover the type.
const (
	matchNone = iota
	matchAny  // */*
	matchType // text/*
	matchFull // text/markdown
)

// acceptQuality returns the quality, in thousandths, that an Accept value
// gives text/markdown and text/html. Integer thousandths keep the comparison
// exact: a qvalue has at most three decimal places.
func acceptQuality(accept string) (md, html int) {
	var mdSpec, htmlSpec int
	for _, elem := range splitUnquoted(accept, ',') {
		typ, sub, q, ok := parseMediaRange(elem)
		if !ok {
			continue
		}
		mdSpec, md = narrower(mdSpec, md, rangeMatch(typ, sub, "text", "markdown"), q)
		htmlSpec, html = narrower(htmlSpec, html, rangeMatch(typ, sub, "text", "html"), q)
	}
	return md, html
}

// narrower folds one matching range into the best match so far. A more
// specific range replaces the quality outright; a range as specific as the
// current one keeps the higher quality of the two.
func narrower(curSpec, curQ, spec, q int) (int, int) {
	switch {
	case spec == matchNone || spec < curSpec:
		return curSpec, curQ
	case spec > curSpec:
		return spec, q
	default:
		return spec, max(curQ, q)
	}
}

// rangeMatch reports how specifically the range typ/sub covers the media
// type wantType/wantSub. Both sides are already lowercase.
func rangeMatch(typ, sub, wantType, wantSub string) int {
	switch {
	case typ == "*" && sub == "*":
		return matchAny
	case typ != wantType:
		return matchNone
	case sub == "*":
		return matchType
	case sub == wantSub:
		return matchFull
	}
	return matchNone
}

// parseMediaRange parses one Accept element into its lowercase type and
// subtype and its quality in thousandths. The quality defaults to 1000.
// Parameters after q are accept extensions and are not read.
func parseMediaRange(elem string) (typ, sub string, q int, ok bool) {
	parts := splitUnquoted(elem, ';')
	typ, sub, found := strings.Cut(trimOWS(parts[0]), "/")
	if !found || !isToken(typ) || !isToken(sub) || (typ == "*" && sub != "*") {
		return "", "", 0, false
	}
	q = 1000
	for _, param := range parts[1:] {
		name, value, found := strings.Cut(param, "=")
		if name = trimOWS(name); !found || (name != "q" && name != "Q") {
			continue
		}
		if q, ok = parseQuality(trimOWS(value)); !ok {
			return "", "", 0, false
		}
		break
	}
	return strings.ToLower(typ), strings.ToLower(sub), q, true
}

// parseQuality parses an RFC 9110 qvalue into thousandths:
//
//	qvalue = ( "0" [ "." 0*3DIGIT ] ) / ( "1" [ "." 0*3("0") ] )
func parseQuality(s string) (int, bool) {
	whole, frac, _ := strings.Cut(s, ".")
	if len(frac) > 3 {
		return 0, false
	}
	switch whole {
	case "0":
		n := 0
		for i := range 3 {
			n *= 10
			if i < len(frac) {
				c := frac[i]
				if c < '0' || c > '9' {
					return 0, false
				}
				n += int(c - '0')
			}
		}
		return n, true
	case "1":
		if strings.Trim(frac, "0") != "" {
			return 0, false
		}
		return 1000, true
	}
	return 0, false
}

// splitUnquoted splits s at every sep that is not inside a quoted string.
// A backslash inside a quoted string escapes the next byte, as the
// quoted-pair rule of RFC 9110 section 5.6.4 allows. An unterminated quote
// runs to the end of s.
func splitUnquoted(s string, sep byte) []string {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case quoted && c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && c == sep:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// trimOWS removes the optional whitespace (spaces and horizontal tabs) HTTP
// allows around list elements and parameters.
func trimOWS(s string) string { return strings.Trim(s, " \t") }

// isToken reports whether s is a non-empty RFC 9110 token. It is checked
// byte by byte so only ASCII passes; a Unicode letter that folds to ASCII
// under case folding must not match a media type.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0:
		default:
			return false
		}
	}
	return true
}
