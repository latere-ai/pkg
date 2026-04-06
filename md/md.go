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

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/goccy/go-yaml"
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
func splitFrontmatter(src []byte) (body, front []byte, ok bool) {
	delim := []byte("---")
	src = bytes.TrimLeft(src, "\n")
	if !bytes.HasPrefix(src, delim) {
		return src, nil, false
	}

	// Find closing delimiter.
	rest := src[len(delim):]
	// Skip the newline after opening delimiter.
	if idx := bytes.IndexByte(rest, '\n'); idx >= 0 {
		rest = rest[idx+1:]
	}

	idx := bytes.Index(rest, delim)
	if idx < 0 {
		return src, nil, false
	}

	front = rest[:idx]
	body = rest[idx+len(delim):]
	// Trim the newline right after the closing delimiter.
	if len(body) > 0 && body[0] == '\n' {
		body = body[1:]
	}
	return body, front, true
}
