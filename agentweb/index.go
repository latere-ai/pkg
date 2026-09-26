// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Index is the list of a site's public pages that every renderer and the
// negotiation middleware read. It decodes from JSON with the field names in
// its tags, so a static site build can emit it beside the pages, and it is
// a plain struct, so a server can build the same value in Go from its
// route table.
//
// Paths in the index (Page.Path, Page.Markdown, and the values of
// Page.Alternates) are origin-relative and start with "/"; renderers join
// them with Origin.
type Index struct {
	// Origin is the scheme and host every path is joined with, such as
	// "https://example.com". A trailing slash is ignored.
	Origin string `json:"origin"`

	// Title names the site. It is the H1 of llms.txt.
	Title string `json:"title"`

	// Summary is the one-paragraph description llms.txt quotes under the
	// title.
	Summary string `json:"summary,omitempty"`

	// Pages are the site's pages in reading order. llms.txt lists them in
	// this order, and its sections appear in the order their first page
	// does.
	Pages []Page `json:"pages"`
}

// Page is one public page.
type Page struct {
	// Path is the page's canonical path, such as "/en/part/chapter".
	// Required and unique within the index.
	Path string `json:"path"`

	// Lang is the page's language code, such as "en". Required when the
	// page has Alternates.
	Lang string `json:"lang,omitempty"`

	// Title is the page's title, the link text in llms.txt.
	Title string `json:"title"`

	// Description is one sentence about the page, the note after its link
	// in llms.txt.
	Description string `json:"description,omitempty"`

	// Section is the llms.txt heading the page is listed under.
	Section string `json:"section,omitempty"`

	// LastMod is the date of the page's last meaningful change, as
	// YYYY-MM-DD or a full RFC 3339 timestamp. It is written to the
	// sitemap as given.
	LastMod string `json:"lastmod,omitempty"`

	// Priority is the sitemap priority, from 0 to 1. Zero means unset and
	// writes no priority element, so a page cannot state the protocol's
	// lowest value of 0.0; 0.1 is the lowest one it can.
	Priority float64 `json:"priority,omitempty"`

	// Markdown is the path of the page's Markdown twin, such as
	// "/en/part/chapter.md". Empty when the page has none.
	Markdown string `json:"markdown,omitempty"`

	// Alternates maps another language code to the path of this page in
	// that language, such as {"zh": "/zh/part/chapter"}. The page itself
	// is not listed; its own Lang and Path complete the set.
	Alternates map[string]string `json:"alternates,omitempty"`
}

// ParseIndex decodes an index from JSON and validates it. Fields it does not
// know are ignored, so a build may add fields before this package reads
// them.
func ParseIndex(data []byte) (*Index, error) {
	var idx Index
	if err := json.Unmarshal(data, &idx); err != nil {
		return nil, fmt.Errorf("agentweb: decode index: %w", err)
	}
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	return &idx, nil
}

// Validate reports the first problem that would make a rendered document
// wrong: an origin that is not an absolute http or https URL without a
// path, a path that is not origin-relative, a repeated path, a Markdown
// twin that is also a page path, an alternate without the page's own
// language, a malformed lastmod, or a priority outside 0 to 1.
func (idx *Index) Validate() error {
	if err := checkOrigin(idx.Origin); err != nil {
		return fmt.Errorf("agentweb: index origin %q: %w", idx.Origin, err)
	}
	pages := make(map[string]bool, len(idx.Pages))
	twins := make(map[string]bool)
	twinOf := make([]string, len(idx.Pages)) // decoded twin path per page, "" when none
	for i, p := range idx.Pages {
		where := fmt.Sprintf("agentweb: index page %d (%q)", i, p.Path)
		key, err := pathKey(p.Path)
		if err != nil {
			return fmt.Errorf("%s: path: %w", where, err)
		}
		if pages[key] {
			return fmt.Errorf("%s: path is listed twice", where)
		}
		pages[key] = true
		if p.Markdown != "" {
			tkey, err := pathKey(p.Markdown)
			if err != nil {
				return fmt.Errorf("%s: markdown %q: %w", where, p.Markdown, err)
			}
			if twins[tkey] {
				return fmt.Errorf("%s: markdown %q is the twin of another page", where, p.Markdown)
			}
			twins[tkey] = true
			twinOf[i] = tkey
		}
		if p.Lang != "" && !isLangCode(p.Lang) {
			return fmt.Errorf("%s: lang %q is not a language code", where, p.Lang)
		}
		if len(p.Alternates) > 0 && p.Lang == "" {
			return fmt.Errorf("%s: alternates need the page's own lang", where)
		}
		for _, lang := range slices.Sorted(maps.Keys(p.Alternates)) {
			alt := p.Alternates[lang]
			switch {
			case !isLangCode(lang) || strings.EqualFold(lang, "x-default"):
				return fmt.Errorf("%s: alternate language %q is not a language code", where, lang)
			case lang == p.Lang:
				return fmt.Errorf("%s: alternate %q repeats the page's own language", where, lang)
			}
			if _, err := pathKey(alt); err != nil {
				return fmt.Errorf("%s: alternate %s %q: %w", where, lang, alt, err)
			}
		}
		if p.LastMod != "" && !isW3CDate(p.LastMod) {
			return fmt.Errorf("%s: lastmod %q is neither YYYY-MM-DD nor RFC 3339", where, p.LastMod)
		}
		if math.IsNaN(p.Priority) || p.Priority < 0 || p.Priority > 1 {
			return fmt.Errorf("%s: priority %v is outside 0 to 1", where, p.Priority)
		}
	}
	for i, key := range twinOf {
		if key != "" && pages[key] {
			p := idx.Pages[i]
			return fmt.Errorf("agentweb: index page %d (%q): markdown %q is also a page path", i, p.Path, p.Markdown)
		}
	}
	return nil
}

// URL joins an origin-relative path with the index origin, percent-encoding
// what the path leaves unencoded. The path is expected to have passed
// Validate; one that does not parse is joined as given.
func (idx *Index) URL(path string) string {
	base := strings.TrimSuffix(idx.Origin, "/")
	u, err := url.Parse(path)
	if err != nil {
		return base + path
	}
	return base + u.EscapedPath()
}

// errNotPath is the reason a value is not an origin-relative path.
var errNotPath = errors.New("not an origin-relative path starting with /")

// pathKey validates an origin-relative path and returns its decoded form,
// the form net/http puts in Request.URL.Path. A path that starts with "//"
// is refused: a URL parser reads it as a host.
func pathKey(p string) (string, error) {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") {
		return "", errNotPath
	}
	u, err := url.Parse(p)
	if err != nil {
		return "", err
	}
	if u.Scheme != "" || u.Host != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(p, "#") {
		return "", errNotPath
	}
	return u.Path, nil
}

// checkOrigin accepts an absolute http or https URL with a host and nothing
// after it but an optional "/".
func checkOrigin(origin string) error {
	if err := checkAbsoluteURL(origin); err != nil {
		return err
	}
	u, err := url.Parse(origin)
	if err != nil {
		return err
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.User != nil {
		return errors.New("an origin carries no path, query, or user")
	}
	return nil
}

// isLangCode reports whether s has the shape of a BCP 47 language tag:
// ASCII letters, digits and hyphens, starting with a letter. The registry
// itself is not consulted.
func isLangCode(s string) bool {
	if s == "" || !isASCIILetter(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; !isASCIILetter(c) && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func isASCIILetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// isW3CDate reports whether s is one of the W3C Datetime forms a sitemap
// lastmod takes: a date, or a complete RFC 3339 timestamp.
func isW3CDate(s string) bool {
	if _, err := time.Parse(time.DateOnly, s); err == nil {
		return true
	}
	_, err := time.Parse(time.RFC3339, s)
	return err == nil
}
