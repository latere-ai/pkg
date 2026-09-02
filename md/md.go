// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package md provides shared Markdown utilities: YAML frontmatter parsing
// and HTML rendering with GitHub Flavored Markdown.
//
// Frontmatter is delimited by "---" lines at the start of the document.
// Use [Parse] for untyped access or [ParseInto] to decode into a struct.
//
// Example:
//
//	front, body, _ := md.Parse(src)
//	html, _ := md.Render(body)
package md

import (
	"bytes"

	"github.com/goccy/go-yaml"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
)

var renderer = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(parser.WithAutoHeadingID()),
)

// Parse splits src into YAML frontmatter and the remaining markdown body.
// If no frontmatter is present, front is nil and body equals src.
func Parse(src []byte) (front map[string]any, body []byte, err error) {
	body, raw, ok := splitFrontmatter(src)
	if !ok {
		return nil, src, nil
	}
	front = make(map[string]any)
	if err := yaml.Unmarshal(raw, &front); err != nil {
		return nil, nil, err
	}
	return front, body, nil
}

// ParseInto decodes YAML frontmatter into v (typically a pointer to a struct)
// and returns the remaining markdown body. If no frontmatter is present,
// v is left unchanged and body equals src.
func ParseInto(src []byte, v any) (body []byte, err error) {
	body, raw, ok := splitFrontmatter(src)
	if !ok {
		return src, nil
	}
	if err := yaml.Unmarshal(raw, v); err != nil {
		return nil, err
	}
	return body, nil
}

// Render converts markdown source to HTML using GFM extensions and
// automatic heading IDs.
func Render(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := renderer.Convert(src, &buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// splitFrontmatter extracts YAML frontmatter from src.
// Returns (body, yamlBytes, true) if frontmatter was found,
// or (src, nil, false) if not.
//
// Both fences must be their own lines. The opening "---" must be followed by
// a newline or end-of-input (so "----" or "---foo" are not fences), and the
// closing fence starts at column one and may have trailing horizontal space.
// This keeps
// an interior "---" inside a YAML value (e.g. `title: "a --- b"`) from
// prematurely closing the block.
func splitFrontmatter(src []byte) (body, front []byte, ok bool) {
	delim := []byte("---")
	src = bytes.TrimLeft(src, "\n")
	if !bytes.HasPrefix(src, delim) {
		return src, nil, false
	}
	// The opening "---" must be its own line: followed by '\n' or EOF.
	afterOpen := src[len(delim):]
	if len(afterOpen) > 0 && afterOpen[0] != '\n' {
		return src, nil, false
	}

	// rest holds everything after the opening fence's terminating newline.
	rest := afterOpen
	if idx := bytes.IndexByte(rest, '\n'); idx >= 0 {
		rest = rest[idx+1:]
	} else {
		// Opening fence at EOF with no body: no closing fence possible.
		return src, nil, false
	}

	// Scan line by line for a column-one closing fence. Leading indentation is
	// significant YAML content (for example, a "---" line in a block scalar).
	for pos := 0; pos <= len(rest); {
		nl := bytes.IndexByte(rest[pos:], '\n')
		var line []byte
		var next int
		if nl < 0 {
			line = rest[pos:]
			next = len(rest)
		} else {
			line = rest[pos : pos+nl]
			next = pos + nl + 1
		}
		if bytes.Equal(bytes.TrimRight(line, " \t"), delim) {
			front = rest[:pos]
			body = rest[next:]
			return body, front, true
		}
		if nl < 0 {
			break
		}
		pos = next
	}
	// Unclosed frontmatter.
	return src, nil, false
}
