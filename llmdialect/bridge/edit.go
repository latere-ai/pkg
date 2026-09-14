// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// Call is what Probe reads off any dialect's request body.
type Call struct {
	Model     string
	HasModel  bool
	Stream    bool
	MaxTokens int64 // max_tokens, max_completion_tokens, max_output_tokens, or generationConfig.maxOutputTokens; 0 when absent
}

// Probe reads the call members off a request body of any dialect. A
// body that is not a JSON object is an error; a member of the wrong
// type is read as absent, because the dialect's own server owns the
// verdict on it.
func Probe(body []byte) (Call, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(body, &top); err != nil {
		return Call{}, fmt.Errorf("the body is not a JSON object: %w", err)
	}
	if top == nil {
		return Call{}, errors.New("the body is null, not a JSON object")
	}
	var c Call
	if raw, ok := top["model"]; ok {
		var s string
		if json.Unmarshal(raw, &s) == nil && s != "" {
			c.Model, c.HasModel = s, true
		}
	}
	if raw, ok := top["stream"]; ok {
		var b bool
		if json.Unmarshal(raw, &b) == nil {
			c.Stream = b
		}
	}
	for _, member := range []string{"max_tokens", "max_completion_tokens", "max_output_tokens"} {
		if raw, ok := top[member]; ok {
			var n int64
			if json.Unmarshal(raw, &n) == nil && n > 0 {
				c.MaxTokens = n
				break
			}
		}
	}
	if raw, ok := top["generationConfig"]; ok && c.MaxTokens == 0 {
		var gc struct {
			MaxOutputTokens int64 `json:"maxOutputTokens"`
		}
		if json.Unmarshal(raw, &gc) == nil && gc.MaxOutputTokens > 0 {
			c.MaxTokens = gc.MaxOutputTokens
		}
	}
	return c, nil
}

// The edits below splice bytes rather than re-encode, so every byte but
// the one member is the caller's or the provider's, and a body the
// scanner cannot read comes back unchanged.

// errNotObject is a body whose top level is not an object.
var errNotObject = errors.New("not a JSON object")

// marshal encodes one of this package's own shapes, a struct of strings,
// integers and booleans, or a string, all of which always marshal. A
// failure is a bug in this package and is a panic.
func marshal(v any) []byte {
	out, err := json.Marshal(v)
	if err != nil {
		panic("bridge: a shape of this package does not marshal: " + err.Error())
	}
	return out
}

// quote renders s as a JSON string. json.Marshal escapes <, >, and &
// as \u003c, \u003e, and \u0026, which every JSON reader decodes to the
// same characters.
func quote(s string) string {
	return string(marshal(s))
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func skipSpace(b []byte, i int) int {
	for i < len(b) && isSpace(b[i]) {
		i++
	}
	return i
}

// skipString returns the index after the string that opens at b[i].
func skipString(b []byte, i int) (int, error) {
	if i >= len(b) || b[i] != '"' {
		return 0, errors.New("expected a string")
	}
	for j := i + 1; j < len(b); j++ {
		switch b[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, errors.New("unterminated string")
}

// skipValue returns the index after the value that starts at b[i].
func skipValue(b []byte, i int) (int, error) {
	i = skipSpace(b, i)
	if i >= len(b) {
		return 0, errors.New("expected a value")
	}
	switch b[i] {
	case '"':
		return skipString(b, i)
	case '{', '[':
		depth := 0
		for j := i; j < len(b); j++ {
			switch b[j] {
			case '"':
				end, err := skipString(b, j)
				if err != nil {
					return 0, err
				}
				j = end - 1
			case '{', '[':
				depth++
			case '}', ']':
				depth--
				if depth == 0 {
					return j + 1, nil
				}
			}
		}
		return 0, errors.New("unterminated object or array")
	default:
		j := i
		for j < len(b) && !isSpace(b[j]) && b[j] != ',' && b[j] != '}' && b[j] != ']' {
			j++
		}
		if j == i {
			return 0, errors.New("expected a value")
		}
		return j, nil
	}
}

// span is where a member sits: the opening quote of its key, and the
// first and one-past-last byte of its value.
type span struct{ key, start, end int }

// member finds the member named key of the object that opens at
// b[start], or ok false when the object has no such member.
func member(b []byte, start int, key string) (s span, ok bool, err error) {
	i := skipSpace(b, start)
	if i >= len(b) || b[i] != '{' {
		return span{}, false, errNotObject
	}
	i++
	for {
		i = skipSpace(b, i)
		if i >= len(b) {
			return span{}, false, errors.New("unterminated object")
		}
		if b[i] == '}' {
			return span{}, false, nil
		}
		if b[i] == ',' {
			i++
			continue
		}
		keyStart := i
		keyEnd, err := skipString(b, i)
		if err != nil {
			return span{}, false, err
		}
		var k string
		if err := json.Unmarshal(b[keyStart:keyEnd], &k); err != nil {
			return span{}, false, err
		}
		i = skipSpace(b, keyEnd)
		if i >= len(b) || b[i] != ':' {
			return span{}, false, errors.New("expected a colon")
		}
		vs := skipSpace(b, i+1)
		ve, err := skipValue(b, vs)
		if err != nil {
			return span{}, false, err
		}
		if k == key {
			return span{key: keyStart, start: vs, end: ve}, true, nil
		}
		i = ve
	}
}

// splice replaces b[start:end] with repl in a fresh slice.
func splice(b []byte, start, end int, repl []byte) []byte {
	out := make([]byte, 0, len(b)-(end-start)+len(repl))
	out = append(out, b[:start]...)
	out = append(out, repl...)
	return append(out, b[end:]...)
}

// insertMember writes `"key":value` as the first member of the object
// that opens at b[objStart], with a comma when the object is not empty.
func insertMember(b []byte, objStart int, key string, value []byte) []byte {
	i := skipSpace(b, objStart) + 1
	next := skipSpace(b, i)
	m := append([]byte(quote(key)+":"), value...)
	if next < len(b) && b[next] != '}' {
		m = append(m, ',')
	}
	return splice(b, i, i, m)
}

// SetModel replaces the value of the top-level model member, or of
// message.model when the top level has none, with name, and returns
// body unchanged when neither is present, the member is not a string,
// or the body cannot be read.
func SetModel(body []byte, name string) []byte {
	repl := []byte(quote(name))
	if s, ok, err := member(body, 0, "model"); err == nil && ok && body[s.start] == '"' {
		return splice(body, s.start, s.end, repl)
	}
	if m, ok, err := member(body, 0, "message"); err == nil && ok {
		if s, ok, err := member(body, m.start, "model"); err == nil && ok && body[s.start] == '"' {
			return splice(body, s.start, s.end, repl)
		}
	}
	return body
}

// SetModelInFrame applies SetModel to the data of every data line of one
// SSE frame and leaves every other byte as it was; a data line is
// written back as "data: " and its data, so "data:x" gains the space.
func SetModelInFrame(frame []byte, name string) []byte {
	var out []byte
	for i, line := range bytes.SplitAfter(frame, []byte("\n")) {
		if i > 0 && len(line) == 0 {
			break
		}
		body := bytes.TrimRight(line, "\r\n")
		if rest, ok := bytes.CutPrefix(body, []byte("data:")); ok {
			data := bytes.TrimPrefix(rest, []byte(" "))
			out = append(out, "data: "...)
			out = append(out, SetModel(data, name)...)
			out = append(out, line[len(body):]...)
			continue
		}
		out = append(out, line...)
	}
	return out
}

// SetIncludeUsage sets stream_options.include_usage to true, replacing
// the member when present and inserting stream_options, or the member
// inside it, when absent. A body the scanner cannot read is returned
// unchanged.
func SetIncludeUsage(body []byte) []byte {
	s, ok, err := member(body, 0, "stream_options")
	if err != nil {
		return body
	}
	if !ok || body[s.start] != '{' {
		if ok {
			return splice(body, s.start, s.end, []byte(`{"include_usage":true}`))
		}
		return insertMember(body, 0, "stream_options", []byte(`{"include_usage":true}`))
	}
	inner, found, err := member(body, s.start, "include_usage")
	if err != nil {
		return body
	}
	if found {
		return splice(body, inner.start, inner.end, []byte("true"))
	}
	return insertMember(body, s.start, "include_usage", []byte("true"))
}

// RemoveMember deletes the top-level member named key with the comma
// that joined it to its neighbours, and returns body unchanged when the
// member is absent or the body cannot be read.
func RemoveMember(body []byte, key string) []byte {
	s, ok, err := member(body, 0, key)
	if err != nil || !ok {
		return body
	}
	start, end := s.key, s.end
	if next := skipSpace(body, end); next < len(body) && body[next] == ',' {
		end = next + 1
	} else {
		prev := start - 1
		for prev > 0 && isSpace(body[prev]) {
			prev--
		}
		if prev > 0 && body[prev] == ',' {
			start = prev
		}
	}
	return splice(body, start, end, nil)
}
