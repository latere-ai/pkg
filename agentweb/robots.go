// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"latere.ai/x/pkg/errwriter"
)

// SignalsPolicy is the Content Signals Policy: the comment block that
// states what each signal means and reserves the refused uses under
// Article 4 of EU Directive 2019/790. [Robots.Policy] prepends it.
//
// The text is the one contentsignals.org's generator writes ahead of the
// groups, reproduced verbatim; Cloudflare's managed robots.txt carries the
// same text wrapped to a wider column.
const SignalsPolicy = `# As a condition of accessing this website, you agree to
# abide by the following content signals:

# (a)  If a content-signal = yes, you may collect content
# for the corresponding use.
# (b)  If a content-signal = no, you may not collect content
# for the corresponding use.
# (c)  If the website operator does not include a content
# signal for a corresponding use, the website operator
# neither grants nor restricts permission via content signal
# with respect to the corresponding use.

# The content signals and their meanings are:

# search: building a search index and providing search
# results (e.g., returning hyperlinks and short excerpts
# from your website's contents).  Search does not include
# providing AI-generated search summaries.
# ai-input: inputting content into one or more AI models
# (e.g., retrieval augmented generation, grounding, or other
# real-time taking of content for generative AI search
# answers).
# ai-train: training or fine-tuning AI models.

# ANY RESTRICTIONS EXPRESSED VIA CONTENT SIGNALS ARE EXPRESS
# RESERVATIONS OF RIGHTS UNDER ARTICLE 4 OF THE EUROPEAN
# UNION DIRECTIVE 2019/790 ON COPYRIGHT AND RELATED RIGHTS
# IN THE DIGITAL SINGLE MARKET.
`

// Robots is a robots.txt file: user-agent groups and the sitemaps that
// close it.
type Robots struct {
	// Policy prepends [SignalsPolicy], followed by an empty line. The
	// policy is a legal statement a publisher chooses to make, so it is
	// off unless set.
	Policy bool

	// Groups are written in order, separated by an empty line. A crawler
	// obeys the one group whose user agent matches it most specifically
	// (RFC 9309 section 2.2.1), so a blocked crawler's group does not need
	// the preferences of the "*" group.
	Groups []Group

	// Sitemaps are absolute URLs, written as Sitemap lines after the
	// groups.
	Sitemaps []string
}

// Group is one robots.txt group: the crawlers it names and the rules they
// follow. It renders as
//
//	User-agent: <each of UserAgents>
//	Content-Signal: <Signals>
//	Allow: <each of Allow>
//	Disallow: <each of Disallow>
//
// with the Content-Signal line left out when Signals is zero. The line
// follows the user agents and precedes the rules, where contentsignals.org
// places it. RFC 9309 gives the order of rules within a group no meaning.
type Group struct {
	// UserAgents are product tokens, or "*" for every crawler. At least
	// one is required.
	UserAgents []string

	// Signals are the usage preferences for what this group may crawl.
	Signals Signals

	// Allow and Disallow are path patterns. Each is empty or starts with
	// "/"; an empty Disallow allows everything, as RFC 9309 defines it.
	Allow    []string
	Disallow []string
}

// WriteRobots renders r to w. It writes nothing when r does not validate.
func WriteRobots(w io.Writer, r Robots) error {
	if err := r.validate(); err != nil {
		return err
	}
	out := errwriter.New(w)
	sep := ""
	if r.Policy {
		out.Print(SignalsPolicy)
		sep = "\n"
	}
	for _, g := range r.Groups {
		out.Print(sep)
		for _, ua := range g.UserAgents {
			out.Printf("User-agent: %s\n", ua)
		}
		if !g.Signals.IsZero() {
			out.Printf("Content-Signal: %s\n", g.Signals)
		}
		for _, p := range g.Allow {
			out.Printf("Allow: %s\n", p)
		}
		for _, p := range g.Disallow {
			out.Printf("Disallow: %s\n", p)
		}
		sep = "\n"
	}
	if len(r.Sitemaps) > 0 {
		out.Print(sep)
		for _, s := range r.Sitemaps {
			out.Printf("Sitemap: %s\n", s)
		}
	}
	return out.Err()
}

// RobotsHandler serves r as robots.txt. The file is rendered once, here, so
// a configuration error surfaces at startup rather than on the first crawl.
func RobotsHandler(r Robots) (http.Handler, error) {
	var b bytes.Buffer
	if err := WriteRobots(&b, r); err != nil {
		return nil, err
	}
	return staticHandler(b.Bytes(), "text/plain; charset=utf-8"), nil
}

// validate rejects a value that would break the line structure of the
// file or that RFC 9309 does not allow in its position.
func (r Robots) validate() error {
	for i, g := range r.Groups {
		if len(g.UserAgents) == 0 {
			return fmt.Errorf("agentweb: robots group %d names no user agent", i)
		}
		for _, ua := range g.UserAgents {
			if ua == "" || strings.ContainsFunc(ua, isRobotsBreak) || strings.ContainsAny(ua, " \t") {
				return fmt.Errorf("agentweb: robots group %d: user agent %q is not a product token", i, ua)
			}
		}
		if err := g.Signals.validate(); err != nil {
			return fmt.Errorf("agentweb: robots group %d: %w", i, err)
		}
		for _, p := range slices.Concat(g.Allow, g.Disallow) {
			if p != "" && (!strings.HasPrefix(p, "/") || strings.ContainsFunc(p, isRobotsBreak) || strings.ContainsAny(p, " \t")) {
				return fmt.Errorf("agentweb: robots group %d: path %q must be empty or a path starting with /", i, p)
			}
		}
	}
	for _, s := range r.Sitemaps {
		if err := checkAbsoluteURL(s); err != nil {
			return fmt.Errorf("agentweb: robots sitemap %q: %w", s, err)
		}
	}
	return nil
}

// isRobotsBreak reports whether c would end a robots.txt line or start a
// comment inside a value.
func isRobotsBreak(c rune) bool { return c == '#' || c < 0x20 || c == 0x7f }

// errNotAbsolute is the reason a URL that must name its own origin does not.
var errNotAbsolute = errors.New("not an absolute http or https URL")

// checkAbsoluteURL accepts an absolute http or https URL with a host, no
// fragment, and nothing that would break a line.
func checkAbsoluteURL(s string) error {
	if strings.ContainsFunc(s, isRobotsBreak) || strings.ContainsAny(s, " \t") {
		return errNotAbsolute
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errNotAbsolute
	}
	return nil
}
