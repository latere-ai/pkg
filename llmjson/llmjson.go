// Package llmjson repairs the JSON a language model returns when it was asked
// for JSON and answered with something close to it.
//
// A model told to reply with a JSON object reliably produces the right keys
// and the wrong encoding. Two mistakes account for nearly all of it: the reply
// arrives wrapped in a markdown code fence, and multi-line string values carry
// literal newlines and tabs where JSON requires \n and \t. Neither is a
// prompting failure that more instructions fix, and neither is a reason to
// discard an otherwise correct answer.
//
// Nothing here parses JSON or validates structure. The functions do the least
// that makes encoding/json able to, so a genuinely malformed reply still fails
// at the decoder where the error is legible.
package llmjson

import "strings"

// Unfence removes a markdown code fence around s, along with the surrounding
// whitespace. A reply that carries no fence is returned trimmed and otherwise
// unchanged.
//
// Only an outer fence goes. A fence inside a string value is content, and
// removing it would corrupt the answer rather than repair it.
func Unfence(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "```") {
		return s
	}
	// Drop the opening fence and its language tag, which sits on the same
	// line: ```json, ```JSON, or a bare ```.
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	} else {
		s = strings.TrimPrefix(s, "```")
	}
	if i := strings.LastIndex(s, "```"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// EscapeControls escapes the control characters a model leaves raw inside
// string values: newline, carriage return and tab. Everything outside a string
// is untouched, so the whitespace that makes a pretty-printed object readable
// stays where it is.
//
// The scan is a two-state machine over bytes rather than a parser. An existing
// escape sequence passes through with the byte it escapes, so \" does not end
// a string and an already-correct \n is not doubled. Input that is not JSON at
// all is returned changed but no less parseable, since the decoder is what
// judges it.
func EscapeControls(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	inString := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inString {
			if c == '"' {
				inString = true
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '"':
			inString = false
			b.WriteByte(c)
		case '\\':
			// Keep an existing escape and whatever it escapes, so a
			// quote inside a string does not look like its end.
			b.WriteByte(c)
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// Repair applies both fixes in the order a reply needs them: the fence comes
// off first, because its own newlines are not string content, and the raw
// control characters are escaped after.
//
// Use it as a second attempt. Decode the reply as it arrived, and only when
// that fails decode Repair of it, so a well-formed answer is never rewritten.
func Repair(s string) string { return EscapeControls(Unfence(s)) }
