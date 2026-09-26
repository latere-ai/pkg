// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"strings"
	"testing"
)

// TestPrefersMarkdownPrecedence is the negotiation rule as a table: Markdown
// is served only when text/markdown carries a strictly higher quality than
// text/html, each quality taken from the most specific range that matches.
func TestPrefersMarkdownPrecedence(t *testing.T) {
	cases := []struct {
		name   string
		accept string
		want   bool
	}{
		// Browsers.
		{"chrome navigation", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7", false},
		{"firefox navigation", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", false},
		{"safari navigation", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", false},

		// Agents that ask for Markdown.
		{"markdown alone", "text/markdown", true},
		{"markdown over html", "text/markdown, text/html;q=0.9", true},
		{"markdown over html and any", "text/markdown, text/html;q=0.9, */*;q=0.8", true},
		{"markdown with charset", "text/markdown;charset=utf-8", true},
		{"markdown only through its q", "text/html;q=0.5, text/markdown;q=0.6", true},
		{"html refused, any accepted", "*/*, text/html;q=0", true},
		{"markdown beats text wildcard", "text/markdown;q=0.9, text/*;q=0.5", true},

		// Ties and defaults serve HTML: it is the page's primary representation.
		{"empty", "", false},
		{"any", "*/*", false},
		{"text wildcard", "text/*", false},
		{"equal explicit", "text/markdown, text/html", false},
		{"equal q", "text/html;q=0.8, text/markdown;q=0.8", false},
		{"html listed first", "text/html, text/markdown", false},
		{"html over markdown", "text/html, text/markdown;q=0.9", false},
		{"markdown refused", "text/markdown;q=0", false},
		{"markdown refused, any accepted", "text/markdown;q=0, */*", false},
		{"neither acceptable", "application/json", false},
		{"plain text only", "text/plain", false},

		// The most specific range decides, not the highest q among matches.
		{"specific markdown below wildcard", "text/markdown;q=0.1, */*;q=1, text/html;q=0.5", false},
		{"specific html below wildcard", "text/html;q=0.1, text/*;q=0.9", true},
		{"type wildcard beats any", "text/*;q=0.2, */*;q=1, text/html;q=0.1", true},

		// Repeated ranges at one specificity take the highest quality.
		{"repeated markdown", "text/markdown;q=0.1, text/markdown;q=0.9, text/html;q=0.5", true},

		// Spelling: case, whitespace, parameters, quoting.
		{"case insensitive", "Text/Markdown, TEXT/HTML;Q=0.5", true},
		{"tabs and spaces", " text/markdown \t;\t q=1 ,\ttext/html ; q=0.2 ", true},
		{"q followed by extension", "text/markdown;q=0.9;ext=1, text/html;q=0.8", true},
		{"quoted comma in parameter", `text/html;q=0.1;x="a, text/markdown;q=0.5, b"`, false},
		{"quoted escape", `text/markdown;q=0.2;x="a\",text/html,b"`, true},
		{"one decimal", "text/markdown;q=1., text/html;q=0.", true},
		{"three decimals", "text/markdown;q=0.001, text/html;q=0.000", true},

		// Malformed elements are skipped, never widened to q=1.
		{"q out of range", "text/markdown;q=2, text/html;q=0.5", false},
		{"q with four decimals", "text/markdown;q=0.1234, text/html;q=0.1", false},
		{"q not a number", "text/markdown;q=high, text/html;q=0.1", false},
		{"q above one", "text/markdown;q=1.001", false},
		{"q empty", "text/markdown;q=, text/html;q=0.1", false},
		{"q negative", "text/markdown;q=-1", false},
		{"q hex float", "text/markdown;q=0x1p-1", false},
		{"missing subtype", "text/, text/markdown;q=0.5", true},
		{"missing type", "/markdown", false},
		{"subtype wildcard only", "*/markdown", false},
		{"no slash", "markdown", false},
		{"two slashes", "text/markdown/x", false},
		{"empty elements", ",,, ,text/markdown,,", true},
		{"parameter without value", "text/markdown;flag, text/html;q=0.1", true},
		{"unterminated quote", `text/markdown;x="abc, text/html`, true},
		{"control character", "text/mark\x00down", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PrefersMarkdown(c.accept); got != c.want {
				md, html := acceptQuality(c.accept)
				t.Errorf("PrefersMarkdown(%q) = %v, want %v (markdown q=%d, html q=%d)", c.accept, got, c.want, md, html)
			}
		})
	}
}

func TestParseQuality(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"0", 0, true},
		{"0.", 0, true},
		{"0.5", 500, true},
		{"0.05", 50, true},
		{"0.123", 123, true},
		{"1", 1000, true},
		{"1.0", 1000, true},
		{"1.000", 1000, true},
		{"", 0, false},
		{"1.1", 0, false},
		{"1.0000", 0, false},
		{"0.1234", 0, false},
		{"0.a", 0, false},
		{"2", 0, false},
		{".5", 0, false},
		{"00.5", 0, false},
		{"+1", 0, false},
	}
	for _, c := range cases {
		got, ok := parseQuality(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("parseQuality(%q) = %d, %v; want %d, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// FuzzPrefersMarkdown holds the parser to two properties on arbitrary input:
// it never panics, and it never chooses Markdown unless the header could
// have named it, either directly or through a wildcard.
func FuzzPrefersMarkdown(f *testing.F) {
	for _, s := range []string{
		"",
		"text/markdown",
		"text/markdown, text/html;q=0.9",
		"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"*/*, text/html;q=0",
		`text/html;x="a,b\"c", text/markdown;q=0.5`,
		`text/markdown;x="`,
		"text/markdown;q=0.1234",
		";;;,,,",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, accept string) {
		got := PrefersMarkdown(accept)
		lower := strings.ToLower(accept)
		if got && !strings.Contains(lower, "markdown") && !strings.Contains(lower, "*") {
			t.Fatalf("PrefersMarkdown(%q) = true without naming markdown or a wildcard", accept)
		}
		md, html := acceptQuality(accept)
		if md < 0 || md > 1000 || html < 0 || html > 1000 {
			t.Fatalf("acceptQuality(%q) = %d, %d; outside 0..1000", accept, md, html)
		}
	})
}
