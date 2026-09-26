# agentweb

Serves a site's public pages to crawlers and AI agents in the conventions
they read today:

| Document or behavior | Convention |
|---|---|
| `robots.txt` with a `Content-Signal` line per group | [RFC 9309](https://www.rfc-editor.org/rfc/rfc9309) and [Content Signals](https://contentsignals.org/) |
| `sitemap.xml` with `lastmod`, `priority`, and hreflang alternates | [sitemaps.org 0.9](https://www.sitemaps.org/protocol.html) |
| `llms.txt`, per language if the site has several | [llms.txt v2](https://llmstxt.org/) |
| `llms-full.txt`, every Markdown body streamed in reading order | The convention documentation platforms established beside llms.txt |
| `Accept: text/markdown` answered with the page's Markdown twin | [RFC 9110 section 12](https://www.rfc-editor.org/rfc/rfc9110#section-12), [RFC 7763](https://www.rfc-editor.org/rfc/rfc7763) |

Standard library only. The package converts nothing: a page's Markdown twin
is written by the site, from its own Markdown source, and the package routes
to it.

## The page index

Every document is rendered from one `Index`. A static build writes it as
JSON beside the pages:

```json
{
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
}
```

`path`, `markdown`, and the `alternates` values are origin-relative paths.
Only `origin` and each page's `path` are required. `lastmod` is
`YYYY-MM-DD` or an RFC 3339 timestamp. A `priority` of zero or absent writes
no priority. Pages are in reading order, and llms.txt sections keep the
order of their first page. Unknown fields are ignored, so a build can add
one before this package reads it.

## A static site with an embedded tree

The build writes the pages, their `.md` twins, and `agentweb.json` into one
directory, and the server embeds it:

```go
//go:embed all:site
var embedded embed.FS

func routes(siteHandler http.Handler) (http.Handler, error) {
	tree, err := fs.Sub(embedded, "site")
	if err != nil {
		return nil, err
	}
	raw, err := fs.ReadFile(tree, "agentweb.json")
	if err != nil {
		return nil, err
	}
	idx, err := agentweb.ParseIndex(raw)
	if err != nil {
		return nil, err
	}

	robots, err := agentweb.RobotsHandler(agentweb.Robots{
		Policy: true,
		Groups: []agentweb.Group{{
			UserAgents: []string{"*"},
			Signals:    agentweb.Signals{Search: agentweb.Yes, AIInput: agentweb.Yes, AITrain: agentweb.No},
			Allow:      []string{"/"},
		}},
		Sitemaps: []string{idx.URL("/sitemap.xml")},
	})
	if err != nil {
		return nil, err
	}
	sitemap, err := agentweb.SitemapHandler(idx, agentweb.SitemapOptions{
		HrefLang: map[string]string{"zh": "zh-Hans"},
		XDefault: "en",
	})
	if err != nil {
		return nil, err
	}
	llmsEN, err := agentweb.LLMsTxtHandler(idx, agentweb.LLMsOptions{Lang: "en"})
	if err != nil {
		return nil, err
	}
	llmsZH, err := agentweb.LLMsTxtHandler(idx, agentweb.LLMsOptions{Lang: "zh", Title: "..."})
	if err != nil {
		return nil, err
	}
	full, err := agentweb.LLMsFullHandler(idx, agentweb.FSOpener(tree), agentweb.LLMsOptions{Lang: "en"})
	if err != nil {
		return nil, err
	}
	pages, err := agentweb.Negotiate(siteHandler, idx, agentweb.NegotiateOptions{
		DescribedBy: func(p agentweb.Page) string {
			if p.Lang == "zh" {
				return "/zh/llms.txt"
			}
			return "/llms.txt"
		},
	})
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.Handle("GET /robots.txt", robots)
	mux.Handle("GET /sitemap.xml", sitemap)
	mux.Handle("GET /llms.txt", llmsEN)
	mux.Handle("GET /zh/llms.txt", llmsZH)
	mux.Handle("GET /llms-full.txt", full)
	mux.Handle("/", pages)
	return mux, nil
}
```

An llms.txt covers the pages under the path it is served from, so the
Chinese file sits under `/zh/`.

## A server that knows its routes

A server builds the same index in Go from its route table:

```go
idx := &agentweb.Index{Origin: "https://example.com", Title: "Example", Summary: "..."}
for _, r := range routes {
	idx.Pages = append(idx.Pages, agentweb.Page{
		Path: r.Path, Title: r.Title, Section: r.Section, Priority: r.Priority,
	})
}
for _, post := range posts {
	idx.Pages = append(idx.Pages, agentweb.Page{
		Path:     "/blog/" + post.Slug,
		Title:    post.Title,
		Section:  "Blog",
		LastMod:  post.Date.Format(time.DateOnly),
		Priority: 0.6,
		Markdown: "/blog/" + post.Slug + ".md",
	})
}
if err := idx.Validate(); err != nil {
	return err
}
```

The twin path must be something the wrapped handler serves: `Negotiate`
hands the rewritten request to it rather than opening files itself.

## Markdown negotiation

`Negotiate` wraps the site's handler. For a GET or HEAD of a page in the
index that has a twin:

- When `text/markdown` carries a strictly higher quality than `text/html`,
  each taken from the most specific matching range, the request is handed to
  the site's handler with its path rewritten to the twin. The site's ETag,
  precompressed siblings, and caching apply unchanged. A successful response
  is sent as `Content-Type: text/markdown; charset=utf-8` with
  `Content-Location` naming the twin.
- Otherwise the page is served as before, with
  `Link: <twin>; rel="alternate"; type="text/markdown"`.

Both carry `Vary: Accept`. A request for the twin's own path gets the
Markdown type and `Link: <page URL>; rel="canonical"`.

| Accept | Served |
|---|---|
| `text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8` (a browser) | HTML |
| `*/*`, `text/*`, or none | HTML |
| `text/markdown, text/html` (a tie) | HTML |
| `text/markdown` | Markdown |
| `text/markdown, text/html;q=0.9` | Markdown |
| `*/*, text/html;q=0` | Markdown |

`PrefersMarkdown` exposes the rule for a handler that routes on its own.

## What is deliberately absent

- **A `Content-Signal` response header.** No specification defines one:
  Content Signals defines the robots.txt line only. The header seen in the
  wild is added by Cloudflare's Markdown for Agents converter to responses
  it converts, with `ai-train=yes` unless the origin set its own.
- **IETF AIPREF `Content-Usage`.** The attachment draft defines a header and
  a robots.txt rule, but the vocabulary it carries states that it does not
  reflect working group consensus, and its categories and values differ from
  Content Signals. The package doc has the full reasoning and the sources.
- **HTML to Markdown conversion.** A site that has Markdown source serves it.

## Serving the twins well

- Give `.md` files the `text/markdown; charset=utf-8` type in the site's own
  handler too, so they compress: `Negotiate` sets the type on the response,
  but a handler that decides compressibility by type decides before that.
- Precompress `.md` twins beside the HTML if the site precompresses at all.
- If a CDN in front offers its own Markdown conversion or managed
  robots.txt, turn those off: the first replaces the site's twins and adds
  its own usage header, and the second prepends a second policy to the
  site's robots.txt.
