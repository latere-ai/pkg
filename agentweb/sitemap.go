// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"latere.ai/x/pkg/errwriter"
)

// SitemapOptions shapes the hreflang alternates of a sitemap.
type SitemapOptions struct {
	// HrefLang maps an index language code to the hreflang value written
	// for it, for a site whose paths use a short code where search engines
	// should see a fuller tag, such as "zh" written as "zh-Hans". A code
	// the map does not name is written as is.
	HrefLang map[string]string

	// XDefault names the language whose version is the x-default
	// alternate, the one served to a reader whose language no version
	// matches. Empty writes no x-default.
	XDefault string
}

// WriteSitemap renders the index as a sitemap (sitemaps.org protocol 0.9)
// to w, one url element per page in index order.
//
// A url element carries loc, then lastmod and priority when the page sets
// them, in the order the protocol's schema requires. A page with
// Alternates also carries one xhtml:link per language version, its own
// included, sorted by language code, followed by the x-default link when
// XDefault names one of those versions; this is the hreflang form search
// engines read from a sitemap. A page without alternates carries no
// hreflang links, since a single language version has nothing to point
// at. The xhtml namespace is declared only when some page uses it.
func WriteSitemap(w io.Writer, idx *Index, opts SitemapOptions) error {
	if err := idx.Validate(); err != nil {
		return err
	}
	if err := opts.validate(); err != nil {
		return err
	}
	out := errwriter.New(w)
	out.Print(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	out.Print(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"`)
	if slices.ContainsFunc(idx.Pages, func(p Page) bool { return len(p.Alternates) > 0 }) {
		out.Print(` xmlns:xhtml="http://www.w3.org/1999/xhtml"`)
	}
	out.Print(">\n")
	for _, p := range idx.Pages {
		out.Print("  <url>\n")
		out.Printf("    <loc>%s</loc>\n", xmlEscape(idx.URL(p.Path)))
		if p.LastMod != "" {
			out.Printf("    <lastmod>%s</lastmod>\n", xmlEscape(p.LastMod))
		}
		if p.Priority > 0 {
			out.Printf("    <priority>%s</priority>\n", formatPriority(p.Priority))
		}
		if len(p.Alternates) > 0 {
			versions := maps.Clone(p.Alternates)
			versions[p.Lang] = p.Path
			for _, lang := range slices.Sorted(maps.Keys(versions)) {
				writeAlternate(out, opts.hreflang(lang), idx.URL(versions[lang]))
			}
			if path, ok := versions[opts.XDefault]; ok {
				writeAlternate(out, "x-default", idx.URL(path))
			}
		}
		out.Print("  </url>\n")
	}
	out.Print("</urlset>\n")
	return out.Err()
}

// SitemapHandler serves the index as sitemap.xml. The document is rendered
// once, here, so a bad index surfaces at startup.
func SitemapHandler(idx *Index, opts SitemapOptions) (http.Handler, error) {
	var b bytes.Buffer
	if err := WriteSitemap(&b, idx, opts); err != nil {
		return nil, err
	}
	return staticHandler(b.Bytes(), "application/xml; charset=utf-8"), nil
}

func writeAlternate(out *errwriter.Writer, hreflang, href string) {
	out.Printf("    <xhtml:link rel=\"alternate\" hreflang=\"%s\" href=\"%s\"/>\n", xmlEscape(hreflang), xmlEscape(href))
}

// hreflang returns the value written for an index language code.
func (o SitemapOptions) hreflang(lang string) string {
	if v, ok := o.HrefLang[lang]; ok {
		return v
	}
	return lang
}

func (o SitemapOptions) validate() error {
	for _, k := range slices.Sorted(maps.Keys(o.HrefLang)) {
		if !isLangCode(k) || !isLangCode(o.HrefLang[k]) {
			return fmt.Errorf("agentweb: sitemap hreflang %q: %q is not a language code", k, o.HrefLang[k])
		}
	}
	if o.XDefault != "" && !isLangCode(o.XDefault) {
		return fmt.Errorf("agentweb: sitemap x-default %q is not a language code", o.XDefault)
	}
	return nil
}

// formatPriority writes a priority with at least one decimal place, so 1
// and 0.5 read "1.0" and "0.5" as sitemaps conventionally write them, and
// with no more places than the value needs.
func formatPriority(p float64) string {
	s := strconv.FormatFloat(p, 'f', -1, 64)
	if !strings.Contains(s, ".") {
		s += ".0"
	}
	return s
}

// xmlEscaper writes the five entities the sitemap protocol requires for
// the characters that are markup in XML.
var xmlEscaper = strings.NewReplacer("&", "&amp;", "'", "&apos;", `"`, "&quot;", ">", "&gt;", "<", "&lt;")

// xmlEscape escapes s for XML character data and attribute values. Every
// value reaching it is validated first, so it holds no control characters
// XML cannot carry.
func xmlEscape(s string) string { return xmlEscaper.Replace(s) }
