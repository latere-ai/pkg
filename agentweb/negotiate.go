// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// markdownType is the Content-Type of a Markdown twin (RFC 7763).
const markdownType = "text/markdown; charset=utf-8"

// NegotiateOptions adds optional discovery links to negotiated responses.
type NegotiateOptions struct {
	// DescribedBy returns the path of the llms.txt that covers a page,
	// such as "/llms.txt" or "/zh/llms.txt", or "" for none. The path is
	// sent as Link rel="describedby" on the page's responses, the link
	// relation llms.txt names for finding the file that describes a page.
	// Nil sends none. It is called once per page when Negotiate builds
	// its table.
	DescribedBy func(p Page) string
}

// Negotiate wraps a site's handler so a page with a Markdown twin answers an
// agent that prefers Markdown with the twin, and answers everyone else with
// the page as before.
//
// For a GET or HEAD of a page path in the index:
//
//   - When [PrefersMarkdown] holds for the Accept header and the page has a
//     twin, next serves the request with its path rewritten to the twin's.
//     The site's own static serving therefore applies unchanged: its ETag,
//     precompressed siblings, and cache headers. A successful response is
//     sent with Content-Type text/markdown; charset=utf-8, whatever type
//     next chose, and Content-Location naming the twin.
//   - Otherwise next serves the page, and a successful or 304 response
//     gains Link: <twin>; rel="alternate"; type="text/markdown" so a
//     client can find the twin without negotiating.
//
// Both answers carry Vary: Accept, added to whatever Vary next sets, so a
// shared cache keeps the two representations apart. A request for a twin's
// own path is served by next with the Markdown Content-Type and
// Link: <page URL>; rel="canonical", which keeps search engines indexing
// the page rather than its twin. Pages without a twin are negotiated for
// nothing; they gain only the describedby link when one is configured.
// Every other request passes through untouched.
//
// Headers are set when next writes its status, not before it runs, so a
// handler that replaces Vary or Content-Type still ends up with them.
func Negotiate(next http.Handler, idx *Index, opts NegotiateOptions) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("agentweb: Negotiate needs a handler to wrap")
	}
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	n := &negotiator{
		next:  next,
		pages: make(map[string]*pageLinks, len(idx.Pages)),
		twins: make(map[string]*twinLinks),
	}
	for _, p := range idx.Pages {
		// Validate has already parsed every path, so these cannot fail;
		// the error is still returned rather than dropped.
		key, err := pathKey(p.Path)
		if err != nil {
			return nil, err
		}
		var describedBy string
		if opts.DescribedBy != nil {
			if d := opts.DescribedBy(p); d != "" {
				if _, err := pathKey(d); err != nil {
					return nil, fmt.Errorf("agentweb: describedby %q for page %q: %w", d, p.Path, err)
				}
				describedBy = fmt.Sprintf("<%s>; rel=\"describedby\"", escapedPath(d))
			}
		}
		if p.Markdown == "" {
			if describedBy != "" {
				n.pages[key] = &pageLinks{describedBy: describedBy}
			}
			continue
		}
		twin, err := url.Parse(p.Markdown)
		if err != nil {
			return nil, err
		}
		n.pages[key] = &pageLinks{
			twinPath:    twin.Path,
			twinRawPath: twin.RawPath,
			alternate:   fmt.Sprintf("<%s>; rel=\"alternate\"; type=\"text/markdown\"", twin.EscapedPath()),
			location:    twin.EscapedPath(),
			describedBy: describedBy,
		}
		n.twins[twin.Path] = &twinLinks{
			canonical:   fmt.Sprintf("<%s>; rel=\"canonical\"", idx.URL(p.Path)),
			describedBy: describedBy,
		}
	}
	return n, nil
}

// negotiator is the handler Negotiate returns: the page and twin tables,
// keyed by the decoded path net/http puts in Request.URL.Path.
type negotiator struct {
	next  http.Handler
	pages map[string]*pageLinks
	twins map[string]*twinLinks
}

// pageLinks holds the precomputed header values for one page path.
type pageLinks struct {
	twinPath    string // decoded twin path, "" when the page has no twin
	twinRawPath string // the twin's encoded path when it differs from twinPath
	alternate   string // Link to the twin, for the HTML response
	location    string // Content-Location of the Markdown response
	describedBy string // Link to the covering llms.txt, or ""
}

// twinLinks holds the precomputed header values for one twin path.
type twinLinks struct {
	canonical   string
	describedBy string
}

func (n *negotiator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		n.next.ServeHTTP(w, r)
		return
	}
	if pl, ok := n.pages[r.URL.Path]; ok {
		if pl.twinPath == "" {
			n.serve(w, r, func(h http.Header, code int) {
				if code/100 == 2 || code == http.StatusNotModified {
					h.Add("Link", pl.describedBy)
				}
			})
			return
		}
		if PrefersMarkdown(strings.Join(r.Header.Values("Accept"), ", ")) {
			twin := r.Clone(r.Context())
			twin.URL.Path, twin.URL.RawPath = pl.twinPath, pl.twinRawPath
			n.serve(w, twin, func(h http.Header, code int) {
				addVary(h, "Accept")
				if code/100 == 2 {
					h.Set("Content-Type", markdownType)
					h.Set("Content-Location", pl.location)
					addLink(h, pl.describedBy)
				}
			})
			return
		}
		n.serve(w, r, func(h http.Header, code int) {
			addVary(h, "Accept")
			if code/100 == 2 || code == http.StatusNotModified {
				h.Add("Link", pl.alternate)
				addLink(h, pl.describedBy)
			}
		})
		return
	}
	if tl, ok := n.twins[r.URL.Path]; ok {
		n.serve(w, r, func(h http.Header, code int) {
			if code/100 == 2 {
				h.Set("Content-Type", markdownType)
				h.Add("Link", tl.canonical)
				addLink(h, tl.describedBy)
			}
		})
		return
	}
	n.next.ServeHTTP(w, r)
}

// serve runs next behind a writer that calls hook once, just before the
// final status is written. A handler that returns without writing is given
// an explicit 200 so the hook still runs, as net/http would send one.
func (n *negotiator) serve(w http.ResponseWriter, r *http.Request, hook func(http.Header, int)) {
	hw := &hookWriter{ResponseWriter: w, hook: hook}
	n.next.ServeHTTP(hw, r)
	if !hw.wroteHeader {
		hw.WriteHeader(http.StatusOK)
	}
}

// addLink adds a Link value unless it is empty.
func addLink(h http.Header, v string) {
	if v != "" {
		h.Add("Link", v)
	}
}

// addVary adds a field name to Vary unless Vary already lists it or "*".
func addVary(h http.Header, field string) {
	for _, v := range h.Values("Vary") {
		for name := range strings.SplitSeq(v, ",") {
			name = trimOWS(name)
			if name == "*" || strings.EqualFold(name, field) {
				return
			}
		}
	}
	h.Add("Vary", field)
}

// escapedPath percent-encodes what an origin-relative path leaves
// unencoded. The path has already passed pathKey.
func escapedPath(p string) string {
	u, err := url.Parse(p)
	if err != nil {
		return p
	}
	return u.EscapedPath()
}

// hookWriter calls hook with the response headers and status once, before
// the first non-informational status reaches the client.
type hookWriter struct {
	http.ResponseWriter
	hook        func(http.Header, int)
	wroteHeader bool
}

func (w *hookWriter) WriteHeader(code int) {
	// An informational status (103 Early Hints) may precede the final one
	// and does not carry the final headers.
	if !w.wroteHeader && code >= 200 {
		w.wroteHeader = true
		w.hook(w.Header(), code)
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *hookWriter) Write(p []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(p)
}

// ReadFrom keeps the zero-copy path net/http offers for file bodies:
// io.Copy into the underlying writer uses its own ReadFrom when it has one.
func (w *hookWriter) ReadFrom(r io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return io.Copy(w.ResponseWriter, r)
}

// Flush sends buffered data to the client, writing the status first.
func (w *hookWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying writer to http.ResponseController.
func (w *hookWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
