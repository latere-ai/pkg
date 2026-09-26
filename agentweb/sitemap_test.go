// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func renderSitemap(t *testing.T, idx *Index, opts SitemapOptions) string {
	t.Helper()
	var b bytes.Buffer
	if err := WriteSitemap(&b, idx, opts); err != nil {
		t.Fatalf("WriteSitemap: %v", err)
	}
	return b.String()
}

// handWrittenPrioritySitemap reproduces the single-line sitemap a
// hand-written Go server emits: one url per line with loc and priority and
// no hreflang. It is the shape the priority-only sitemap replaces.
func handWrittenPrioritySitemap(origin string, routes [][2]string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">` + "\n")
	for _, r := range routes {
		fmt.Fprintf(&b, "  <url><loc>%s%s</loc><priority>%s</priority></url>\n", origin, r[0], r[1])
	}
	b.WriteString("</urlset>\n")
	return b.String()
}

// staticBuildSitemap reproduces a static build's hreflang sitemap: for each
// path, one url per language version, each carrying the whole alternate set
// and an x-default pointing at the English version.
func staticBuildSitemap(origin string, paths []string, langs []string, hreflang map[string]string) string {
	loc := func(lang, p string) string { return origin + "/" + lang + "/" + p }
	var urls []string
	for _, p := range paths {
		var alts []string
		for _, l := range langs {
			alts = append(alts, fmt.Sprintf(`    <xhtml:link rel="alternate" hreflang="%s" href="%s"/>`, hreflang[l], loc(l, p)))
		}
		alts = append(alts, fmt.Sprintf(`    <xhtml:link rel="alternate" hreflang="x-default" href="%s"/>`, loc("en", p)))
		for _, l := range langs {
			urls = append(urls, fmt.Sprintf("  <url>\n    <loc>%s</loc>\n%s\n  </url>", loc(l, p), strings.Join(alts, "\n")))
		}
	}
	return `<?xml version="1.0" encoding="UTF-8"?>` + "\n" +
		`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">` + "\n" +
		strings.Join(urls, "\n") + "\n</urlset>\n"
}

// TestSitemapMatchesStaticBuildShape renders a bilingual index and requires
// the bytes a static build's hand-written generator produces for the same
// pages: loc, the full alternate set with the short "zh" code written as
// "zh-Hans", then x-default.
func TestSitemapMatchesStaticBuildShape(t *testing.T) {
	paths := []string{"", "foundations/why", "practice/deploy"}
	idx := &Index{Origin: "https://example.com"}
	for _, p := range paths {
		for _, l := range []string{"en", "zh"} {
			other := map[string]string{"en": "zh", "zh": "en"}[l]
			idx.Pages = append(idx.Pages, Page{
				Path:       "/" + l + "/" + p,
				Lang:       l,
				Title:      p,
				Alternates: map[string]string{other: "/" + other + "/" + p},
			})
		}
	}
	hreflang := map[string]string{"en": "en", "zh": "zh-Hans"}
	got := renderSitemap(t, idx, SitemapOptions{HrefLang: map[string]string{"zh": "zh-Hans"}, XDefault: "en"})
	want := staticBuildSitemap("https://example.com", paths, []string{"en", "zh"}, hreflang)
	if got != want {
		t.Errorf("sitemap differs from the static build's\n--- got\n%s--- want\n%s", got, want)
	}
}

type sitemapDoc struct {
	XMLName xml.Name     `xml:"urlset"`
	URLs    []sitemapURL `xml:"url"`
}

type sitemapURL struct {
	Loc      string `xml:"loc"`
	LastMod  string `xml:"lastmod"`
	Priority string `xml:"priority"`
}

func parseSitemap(t *testing.T, s string) sitemapDoc {
	t.Helper()
	var d sitemapDoc
	if err := xml.Unmarshal([]byte(s), &d); err != nil {
		t.Fatalf("sitemap does not parse: %v\n%s", err, s)
	}
	return d
}

// TestSitemapMatchesHandWrittenPriorityShape builds a priority-only index
// in Go, as a server does from its route table, and requires the same urls
// and priorities as the hand-written single-line sitemap, in its order,
// with no xhtml namespace.
func TestSitemapMatchesHandWrittenPriorityShape(t *testing.T) {
	routes := [][2]string{
		{"/", "1.0"},
		{"/products", "0.8"},
		{"/blog", "0.7"},
		{"/about", "0.5"},
		{"/legal/terms", "0.3"},
		{"/blog/first-post", "0.6"},
	}
	idx := &Index{Origin: "https://example.com"}
	for _, r := range routes {
		var p float64
		if _, err := fmt.Sscan(r[1], &p); err != nil {
			t.Fatal(err)
		}
		idx.Pages = append(idx.Pages, Page{Path: r[0], Priority: p})
	}
	got := renderSitemap(t, idx, SitemapOptions{})
	if strings.Contains(got, "xmlns:xhtml") {
		t.Error("a sitemap without alternates declares the xhtml namespace")
	}
	want := handWrittenPrioritySitemap("https://example.com", routes)
	if g, w := parseSitemap(t, got), parseSitemap(t, want); !reflect.DeepEqual(g, w) {
		t.Errorf("sitemap urls differ from the hand-written one\n got %+v\nwant %+v", g, w)
	}

	const golden = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://example.com/</loc>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://example.com/products</loc>
    <priority>0.8</priority>
  </url>
`
	if !strings.HasPrefix(got, golden) {
		t.Errorf("sitemap head =\n%s\nwant prefix\n%s", got, golden)
	}
}

func TestSitemapElementOrderAndEscaping(t *testing.T) {
	idx := &Index{Origin: "https://example.com", Pages: []Page{
		{Path: "/a&b/it's", Lang: "en", LastMod: "2026-09-20", Priority: 0.75, Alternates: map[string]string{"de": "/de/a", "zh": "/zh/a"}},
		{Path: "/plain", LastMod: "2026-09-21T08:00:00+02:00"},
	}}
	got := renderSitemap(t, idx, SitemapOptions{XDefault: "fr"})
	const want = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9" xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url>
    <loc>https://example.com/a&amp;b/it&apos;s</loc>
    <lastmod>2026-09-20</lastmod>
    <priority>0.75</priority>
    <xhtml:link rel="alternate" hreflang="de" href="https://example.com/de/a"/>
    <xhtml:link rel="alternate" hreflang="en" href="https://example.com/a&amp;b/it&apos;s"/>
    <xhtml:link rel="alternate" hreflang="zh" href="https://example.com/zh/a"/>
  </url>
  <url>
    <loc>https://example.com/plain</loc>
    <lastmod>2026-09-21T08:00:00+02:00</lastmod>
  </url>
</urlset>
`
	if got != want {
		t.Errorf("sitemap mismatch\n--- got\n%s--- want\n%s", got, want)
	}
	parseSitemap(t, got)
}

func TestSitemapXDefaultFromAlternate(t *testing.T) {
	idx := &Index{Origin: "https://example.com", Pages: []Page{
		{Path: "/zh/a", Lang: "zh", Alternates: map[string]string{"en": "/en/a"}},
		{Path: "/zh/only", Lang: "zh"},
	}}
	got := renderSitemap(t, idx, SitemapOptions{XDefault: "en"})
	if !strings.Contains(got, `<xhtml:link rel="alternate" hreflang="x-default" href="https://example.com/en/a"/>`) {
		t.Errorf("x-default must point at the English alternate:\n%s", got)
	}
	if strings.Count(got, "x-default") != 1 {
		t.Errorf("a single-language page must carry no hreflang links:\n%s", got)
	}
}

func TestFormatPriority(t *testing.T) {
	for p, want := range map[float64]string{1: "1.0", 0.8: "0.8", 0.5: "0.5", 0.1: "0.1", 0.75: "0.75", 0.333: "0.333"} {
		if got := formatPriority(p); got != want {
			t.Errorf("formatPriority(%v) = %q, want %q", p, got, want)
		}
	}
}

func TestSitemapRejects(t *testing.T) {
	good := &Index{Origin: "https://example.com", Pages: []Page{{Path: "/"}}}
	cases := map[string]struct {
		idx  *Index
		opts SitemapOptions
	}{
		"bad index":         {&Index{Origin: "example.com"}, SitemapOptions{}},
		"bad hreflang key":  {good, SitemapOptions{HrefLang: map[string]string{"z h": "zh"}}},
		"bad hreflang":      {good, SitemapOptions{HrefLang: map[string]string{"zh": "zh Hans"}}},
		"bad x-default":     {good, SitemapOptions{XDefault: "e n"}},
		"x-default as lang": {good, SitemapOptions{XDefault: "-"}},
	}
	for name, c := range cases {
		var b bytes.Buffer
		if err := WriteSitemap(&b, c.idx, c.opts); err == nil || b.Len() != 0 {
			t.Errorf("%s: WriteSitemap err = %v, wrote %d bytes", name, err, b.Len())
		}
		if _, err := SitemapHandler(c.idx, c.opts); err == nil {
			t.Errorf("%s: SitemapHandler accepted it", name)
		}
	}
	if err := WriteSitemap(failWriter{}, good, SitemapOptions{}); !errors.Is(err, errWrite) {
		t.Errorf("WriteSitemap error = %v, want the writer's error", err)
	}
}

func TestSitemapHandler(t *testing.T) {
	h, err := SitemapHandler(&Index{Origin: "https://example.com", Pages: []Page{{Path: "/", Priority: 1}}}, SitemapOptions{})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sitemap.xml", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != "application/xml; charset=utf-8" {
		t.Fatalf("GET = %d, Content-Type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Body.String(), "<priority>1.0</priority>") {
		t.Errorf("body = %s", rec.Body.String())
	}
}
