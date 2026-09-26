// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"latere.ai/x/pkg/errwriter"
)

// LLMsOptions selects and titles the pages an llms.txt or llms-full.txt
// file lists.
type LLMsOptions struct {
	// Lang keeps only the pages in this language. Empty keeps every page.
	// An llms.txt covers the pages under the path it is served from, so a
	// site with one tree per language can serve each tree's file from that
	// tree, such as /zh/llms.txt for the pages under /zh/.
	Lang string

	// Title and Summary replace the index's title and summary, for a file
	// written in a language other than the index's.
	Title   string
	Summary string

	// Details is Markdown written between the summary and the first
	// section: how to read the site, what its links point at. The format
	// allows any Markdown there except headings, so a line that opens a
	// heading is refused.
	Details string

	// DefaultSection is the heading for pages that name no section. Empty
	// means "Pages".
	DefaultSection string

	// CacheControl is the Cache-Control value served with the document.
	// Empty sends [DefaultCacheControl].
	CacheControl string
}

// WriteLLMsTxt renders an llms.txt file (llmstxt.org) for the index to w:
//
//	# Title
//
//	> Summary
//
//	Details
//
//	## Section
//
//	- [Page title](https://example.com/page.md): Description
//
// Pages are listed in index order under their Section, and sections appear
// in the order of their first page. A page's link points at its Markdown
// twin when it has one, since the format asks for links to LLM-readable
// content, and at the page itself otherwise. The title and every listed
// page need a title; the summary, details and descriptions are optional.
func WriteLLMsTxt(w io.Writer, idx *Index, opts LLMsOptions) error {
	pages, err := llmsPages(idx, opts)
	if err != nil {
		return err
	}
	out := errwriter.New(w)
	writeLLMsHeader(out, idx, opts)

	var order []string
	bySection := map[string][]Page{}
	for _, p := range pages {
		s := oneLine(p.Section)
		if s == "" {
			s = opts.defaultSection()
		}
		if _, seen := bySection[s]; !seen {
			order = append(order, s)
		}
		bySection[s] = append(bySection[s], p)
	}
	for _, s := range order {
		out.Printf("\n## %s\n\n", s)
		for _, p := range bySection[s] {
			target := p.Path
			if p.Markdown != "" {
				target = p.Markdown
			}
			out.Printf("- [%s](%s)", escapeLinkText(oneLine(p.Title)), linkDestination(idx.URL(target)))
			if d := oneLine(p.Description); d != "" {
				out.Printf(": %s", d)
			}
			out.Print("\n")
		}
	}
	return out.Err()
}

// LLMsTxtHandler serves the index as llms.txt. The file is rendered once,
// here, so a bad index surfaces at startup.
func LLMsTxtHandler(idx *Index, opts LLMsOptions) (http.Handler, error) {
	var b bytes.Buffer
	if err := WriteLLMsTxt(&b, idx, opts); err != nil {
		return nil, err
	}
	cc, err := cacheControl(opts.CacheControl)
	if err != nil {
		return nil, err
	}
	return staticHandler(b.Bytes(), "text/plain; charset=utf-8", cc), nil
}

// Opener opens the Markdown twin at an index path, such as
// "/en/part/chapter.md". The caller closes what it returns.
type Opener func(markdownPath string) (io.ReadCloser, error)

// FSOpener opens twins from fsys, reading the index path without its
// leading slash: "/en/part/chapter.md" opens "en/part/chapter.md". A
// site that embeds its built tree passes that tree, rooted with fs.Sub
// where the build output sits in a subdirectory.
func FSOpener(fsys fs.FS) Opener {
	return func(markdownPath string) (io.ReadCloser, error) {
		return fsys.Open(strings.TrimPrefix(markdownPath, "/"))
	}
}

// WriteLLMsFull writes llms-full.txt to w: the llms.txt header, then the
// Markdown body of every selected page that has a twin, in index order.
// Each body follows a thematic break and a line naming the page it came
// from:
//
//	---
//
//	Source: https://example.com/en/part/chapter
//
// llms-full.txt is a convention documentation platforms established beside
// llms.txt, not part of the llms.txt proposal, which is why its layout is
// this package's own. Bodies are copied from open to w one at a time, so
// the whole site is never held in memory.
func WriteLLMsFull(w io.Writer, idx *Index, open Opener, opts LLMsOptions) error {
	if open == nil {
		return errors.New("agentweb: llms-full.txt needs an opener")
	}
	pages, err := llmsPages(idx, opts)
	if err != nil {
		return err
	}
	out := errwriter.New(w)
	writeLLMsHeader(out, idx, opts)
	for _, p := range pages {
		if p.Markdown == "" {
			continue
		}
		out.Printf("\n---\n\nSource: %s\n\n", idx.URL(p.Path))
		if err := out.Err(); err != nil {
			return err
		}
		if err := copyBody(out, open, p.Markdown); err != nil {
			return err
		}
	}
	return out.Err()
}

// LLMsFullHandler serves llms-full.txt, streaming each twin through open on
// every GET.
//
// It reads every twin once, here, so a twin the index names but the site
// does not have fails at startup rather than midway through a response. A
// read that still fails after the response has started is logged, and the connection is aborted with http.ErrAbortHandler, so the
// client sees a truncated transfer rather than a file that looks complete.
func LLMsFullHandler(idx *Index, open Opener, opts LLMsOptions) (http.Handler, error) {
	if err := WriteLLMsFull(io.Discard, idx, open, opts); err != nil {
		return nil, err
	}
	cc, err := cacheControl(opts.CacheControl)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowRead(w, r) {
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", cc)
		if r.Method == http.MethodHead {
			w.WriteHeader(http.StatusOK)
			return
		}
		cw := &countingWriter{w: w}
		err := WriteLLMsFull(cw, idx, open, opts)
		if err == nil {
			return
		}
		slog.ErrorContext(r.Context(), "agentweb: serving llms-full.txt", "err", err, "bytes_written", cw.n)
		if cw.n == 0 {
			http.Error(w, "llms-full.txt is unavailable", http.StatusInternalServerError)
			return
		}
		panic(http.ErrAbortHandler)
	}), nil
}

// copyBody streams one twin into out and ends it with a newline when the
// twin does not, so the next page's break starts on a line of its own.
func copyBody(out *errwriter.Writer, open Opener, path string) error {
	f, err := open(path)
	if err != nil {
		return fmt.Errorf("agentweb: open markdown %q: %w", path, err)
	}
	last := &lastByteWriter{w: out}
	_, copyErr := io.Copy(last, f)
	closeErr := f.Close()
	if copyErr != nil {
		return fmt.Errorf("agentweb: copy markdown %q: %w", path, copyErr)
	}
	if closeErr != nil {
		return fmt.Errorf("agentweb: close markdown %q: %w", path, closeErr)
	}
	if last.n > 0 && last.last != '\n' {
		out.Print("\n")
	}
	return out.Err()
}

// llmsPages validates what an llms.txt needs and returns the pages the
// options select.
func llmsPages(idx *Index, opts LLMsOptions) ([]Page, error) {
	if err := idx.Validate(); err != nil {
		return nil, err
	}
	if oneLine(opts.title(idx)) == "" {
		return nil, errors.New("agentweb: llms.txt needs a title")
	}
	if line, ok := headingLine(opts.Details); ok {
		return nil, fmt.Errorf("agentweb: llms.txt details may not hold a heading: %q", line)
	}
	var pages []Page
	for _, p := range idx.Pages {
		if opts.Lang != "" && p.Lang != opts.Lang {
			continue
		}
		if oneLine(p.Title) == "" {
			return nil, fmt.Errorf("agentweb: llms.txt page %q has no title", p.Path)
		}
		pages = append(pages, p)
	}
	return pages, nil
}

// writeLLMsHeader writes the H1, the summary blockquote, and the details.
func writeLLMsHeader(out *errwriter.Writer, idx *Index, opts LLMsOptions) {
	out.Printf("# %s\n", oneLine(opts.title(idx)))
	if summary := strings.TrimSpace(opts.summary(idx)); summary != "" {
		out.Print("\n")
		for line := range strings.SplitSeq(summary, "\n") {
			if line = strings.TrimRight(line, " \t\r"); line == "" {
				out.Print(">\n")
			} else {
				out.Printf("> %s\n", line)
			}
		}
	}
	if details := strings.Trim(opts.Details, "\r\n"); strings.TrimSpace(details) != "" {
		out.Printf("\n%s\n", details)
	}
}

func (o LLMsOptions) title(idx *Index) string {
	if o.Title != "" {
		return o.Title
	}
	return idx.Title
}

func (o LLMsOptions) summary(idx *Index) string {
	if o.Summary != "" {
		return o.Summary
	}
	return idx.Summary
}

func (o LLMsOptions) defaultSection() string {
	if s := oneLine(o.DefaultSection); s != "" {
		return s
	}
	return "Pages"
}

// headingLine returns the first line of md that opens an ATX heading: up
// to three spaces, one to six "#", then a space, a tab, or the end of the
// line.
func headingLine(md string) (string, bool) {
	for line := range strings.SplitSeq(md, "\n") {
		rest := strings.TrimLeft(line, " ")
		if len(line)-len(rest) > 3 {
			continue
		}
		hashes := len(rest) - len(strings.TrimLeft(rest, "#"))
		if hashes == 0 || hashes > 6 {
			continue
		}
		if after := rest[hashes:]; after == "" || after[0] == ' ' || after[0] == '\t' || after[0] == '\r' {
			return line, true
		}
	}
	return "", false
}

// oneLine collapses every run of whitespace, line breaks included, into one
// space, so a value cannot end a list item or a heading early.
func oneLine(s string) string { return strings.Join(strings.Fields(s), " ") }

// linkTextEscaper escapes the characters that would end or nest a Markdown
// link's text.
var linkTextEscaper = strings.NewReplacer(`\`, `\\`, "[", `\[`, "]", `\]`)

func escapeLinkText(s string) string { return linkTextEscaper.Replace(s) }

// linkDestination percent-encodes the parentheses a URL path may carry
// unencoded, which would otherwise end a Markdown link destination early.
func linkDestination(u string) string {
	return strings.NewReplacer("(", "%28", ")", "%29").Replace(u)
}

// countingWriter counts the bytes that reached the client, which decides
// whether a failure can still be answered with a status.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// lastByteWriter remembers the last byte written through it.
type lastByteWriter struct {
	w    io.Writer
	n    int64
	last byte
}

func (l *lastByteWriter) Write(p []byte) (int, error) {
	n, err := l.w.Write(p)
	if n > 0 {
		l.n += int64(n)
		l.last = p[n-1]
	}
	return n, err
}
