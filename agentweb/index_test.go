// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

// contractJSON is the index shape a static site build emits, field for
// field. The names are a contract between the build and this package.
const contractJSON = `{
  "origin": "https://example.com",
  "title": "Site title",
  "summary": "One-paragraph summary for llms.txt",
  "pages": [
    {
      "path": "/en/part/chapter",
      "lang": "en",
      "title": "Page title",
      "description": "One sentence",
      "section": "Part I: Foundations",
      "lastmod": "2026-09-20",
      "priority": 0.6,
      "markdown": "/en/part/chapter.md",
      "alternates": { "zh": "/zh/part/chapter" }
    }
  ]
}`

func TestParseIndexContract(t *testing.T) {
	idx, err := ParseIndex([]byte(contractJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := &Index{
		Origin:  "https://example.com",
		Title:   "Site title",
		Summary: "One-paragraph summary for llms.txt",
		Pages: []Page{{
			Path:        "/en/part/chapter",
			Lang:        "en",
			Title:       "Page title",
			Description: "One sentence",
			Section:     "Part I: Foundations",
			LastMod:     "2026-09-20",
			Priority:    0.6,
			Markdown:    "/en/part/chapter.md",
			Alternates:  map[string]string{"zh": "/zh/part/chapter"},
		}},
	}
	if !reflect.DeepEqual(idx, want) {
		t.Errorf("ParseIndex =\n%+v\nwant\n%+v", idx, want)
	}
}

func TestParseIndexOptionalFieldsAndUnknownFields(t *testing.T) {
	idx, err := ParseIndex([]byte(`{"origin":"https://example.com/","title":"T","generator":"build 7",
		"pages":[{"path":"/","title":"Home","extra":{"a":1}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(idx.Pages) != 1 || idx.Pages[0].Path != "/" || idx.Pages[0].Priority != 0 || idx.Pages[0].Markdown != "" {
		t.Errorf("optional fields decoded as %+v", idx.Pages[0])
	}
	if got := idx.URL("/a"); got != "https://example.com/a" {
		t.Errorf("URL with a trailing-slash origin = %q", got)
	}
}

func TestParseIndexRejectsBadJSON(t *testing.T) {
	for _, s := range []string{``, `{`, `{"pages":"x"}`, `{"origin":"https://example.com"} trailing`, `{"origin":"example.com","pages":[]}`} {
		if _, err := ParseIndex([]byte(s)); err == nil {
			t.Errorf("ParseIndex(%q) accepted it", s)
		}
	}
}

func TestIndexURL(t *testing.T) {
	idx := &Index{Origin: "https://example.com"}
	cases := map[string]string{
		"/":             "https://example.com/",
		"/en/a":         "https://example.com/en/a",
		"/zh/文":         "https://example.com/zh/%E6%96%87",
		"/a%20b":        "https://example.com/a%20b",
		"/a b":          "https://example.com/a%20b",
		"/it's/(x)&y":   "https://example.com/it's/(x)&y",
		"/bad%zzescape": "https://example.com/bad%zzescape",
	}
	for in, want := range cases {
		if got := idx.URL(in); got != want {
			t.Errorf("URL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	page := func(mut func(*Page)) Index {
		p := Page{Path: "/en/a", Lang: "en", Title: "A", Markdown: "/en/a.md", Alternates: map[string]string{"zh": "/zh/a"}}
		mut(&p)
		return Index{Origin: "https://example.com", Pages: []Page{p}}
	}
	ok := []Index{
		{Origin: "http://example.com"},
		{Origin: "https://example.com/"},
		{Origin: "https://example.com:8443"},
		page(func(*Page) {}),
		page(func(p *Page) { p.LastMod = "2026-09-20T10:00:00Z" }),
		page(func(p *Page) { p.Priority = 1 }),
		page(func(p *Page) { p.Lang = "zh-Hans"; p.Alternates = map[string]string{"en": "/en/b"} }),
		page(func(p *Page) { p.Alternates = nil; p.Lang = "" }),
	}
	for i, idx := range ok {
		if err := idx.Validate(); err != nil {
			t.Errorf("valid index %d refused: %v", i, err)
		}
	}

	bad := map[string]Index{
		"empty origin":              {},
		"relative origin":           {Origin: "example.com"},
		"origin with path":          {Origin: "https://example.com/docs"},
		"origin with query":         {Origin: "https://example.com/?a=1"},
		"origin with empty query":   {Origin: "https://example.com/?"},
		"origin with user":          {Origin: "https://u@example.com"},
		"origin with fragment":      {Origin: "https://example.com/#x"},
		"ftp origin":                {Origin: "ftp://example.com"},
		"empty path":                page(func(p *Page) { p.Path = "" }),
		"relative path":             page(func(p *Page) { p.Path = "en/a" }),
		"protocol-relative path":    page(func(p *Page) { p.Path = "//evil.example/a" }),
		"path with query":           page(func(p *Page) { p.Path = "/en/a?x=1" }),
		"path with empty query":     page(func(p *Page) { p.Path = "/en/a?" }),
		"path with fragment":        page(func(p *Page) { p.Path = "/en/a#top" }),
		"path with bad escape":      page(func(p *Page) { p.Path = "/en/%zz" }),
		"path with control":         page(func(p *Page) { p.Path = "/en/\x01" }),
		"bad markdown":              page(func(p *Page) { p.Markdown = "a.md" }),
		"markdown is the page":      page(func(p *Page) { p.Markdown = "/en/a" }),
		"alternates without lang":   page(func(p *Page) { p.Lang = "" }),
		"bad lang":                  page(func(p *Page) { p.Lang = "e n" }),
		"lang starting with digit":  page(func(p *Page) { p.Lang = "1en" }),
		"bad alternate lang":        page(func(p *Page) { p.Alternates = map[string]string{"z h": "/zh/a"} }),
		"x-default alternate":       page(func(p *Page) { p.Alternates = map[string]string{"x-default": "/a"} }),
		"alternate repeats own":     page(func(p *Page) { p.Alternates = map[string]string{"en": "/en/b"} }),
		"bad alternate path":        page(func(p *Page) { p.Alternates = map[string]string{"zh": "zh/a"} }),
		"lastmod wrong format":      page(func(p *Page) { p.LastMod = "20/09/2026" }),
		"lastmod impossible date":   page(func(p *Page) { p.LastMod = "2026-02-30" }),
		"priority above one":        page(func(p *Page) { p.Priority = 1.5 }),
		"priority negative":         page(func(p *Page) { p.Priority = -0.1 }),
		"priority not a number":     page(func(p *Page) { p.Priority = math.NaN() }),
		"duplicate page":            {Origin: "https://example.com", Pages: []Page{{Path: "/a"}, {Path: "/a"}}},
		"duplicate after decoding":  {Origin: "https://example.com", Pages: []Page{{Path: "/a b"}, {Path: "/a%20b"}}},
		"shared twin":               {Origin: "https://example.com", Pages: []Page{{Path: "/a", Markdown: "/x.md"}, {Path: "/b", Markdown: "/x.md"}}},
		"twin is another page path": {Origin: "https://example.com", Pages: []Page{{Path: "/a", Markdown: "/b"}, {Path: "/b"}}},
	}
	for name, idx := range bad {
		err := idx.Validate()
		if err == nil {
			t.Errorf("%s: Validate accepted it", name)
			continue
		}
		if !strings.HasPrefix(err.Error(), "agentweb: ") {
			t.Errorf("%s: error %q lacks the package prefix", name, err)
		}
	}
}
