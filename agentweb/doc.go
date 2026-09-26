// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package agentweb serves a site's public pages to crawlers and AI agents in
// the open conventions they read: robots.txt with Content Signals usage
// preferences, a sitemap with hreflang alternates, llms.txt and
// llms-full.txt, and Accept-header negotiation that answers an agent asking
// for Markdown with the page's Markdown twin.
//
// Everything reads one [Index], the site's public pages in reading order. A
// static build can emit it as JSON beside the pages and a server can decode
// it with [ParseIndex]; a server that knows its routes can build the same
// value in Go. The renderers ([WriteRobots], [WriteSitemap], [WriteLLMsTxt],
// [WriteLLMsFull]) write to an io.Writer, and each has a handler that
// validates once at construction, so a bad index fails at startup rather
// than on the first crawl. [Negotiate] wraps the site's own handler.
//
// The package holds no policy. Which usage preferences a site states,
// which crawlers it blocks, and whether it publishes the Content Signals
// Policy text are the site's configuration; the zero value of every option
// states nothing. It converts nothing either: a page's Markdown twin is
// written by the site, which has the Markdown source, and this package only
// routes to it.
//
// # Usage preferences
//
// [Signals] carries the three Content Signals categories, search, ai-input
// and ai-train, each yes, no, or unset, and a [Group] renders them as a
// Content-Signal line inside its robots.txt group:
//
//	User-agent: *
//	Content-Signal: ai-train=no, search=yes, ai-input=yes
//	Allow: /
//
// The line follows the group's user agents and precedes its rules, the
// categories are written in the order contentsignals.org uses throughout,
// an unset category is left out, and [SignalsPolicy] is the comment block
// the Content Signals generator prepends to the file.
//
// There is no Content-Signal HTTP response header here, because no
// specification defines one. contentsignals.org defines only the robots.txt
// line, and the Internet-Draft that registers the category labels
// (draft-romm-aipref-contentsignals-00, expired April 2026) defines only
// the labels. The header in circulation is emitted by Cloudflare's Markdown
// for Agents converter on the responses it converts, where it defaults to
// ai-train=yes; a site that serves its own Markdown through [Negotiate]
// needs neither the converter nor its header.
//
// There is no Content-Usage field or rule either, which the IETF AIPREF
// working group's attachment draft (draft-ietf-aipref-attach-05, August
// 2026) does define, as both an HTTP header and a robots.txt rule. It was
// left out on purpose: the vocabulary it carries (draft-ietf-aipref-vocab-08,
// September 2026) states that its contents do not reflect working group
// consensus; its categories are not the Content Signals ones (train-ai,
// ai-use and search, where AIPREF search overrides the other two, against
// ai-train, ai-input and search); and its values are y and n rather than
// yes and no. Writing both would state one preference twice in two
// vocabularies whose meanings differ, and a reader combining them takes
// the most restrictive. Once the vocabulary settles, a Content-Usage
// rendering of [Signals] can be added beside the Content-Signal line
// without changing the type.
//
// # Sources
//
//   - Content Signals: https://contentsignals.org/
//   - Content Signals category labels:
//     https://datatracker.ietf.org/doc/draft-romm-aipref-contentsignals/
//   - Cloudflare managed robots.txt, which prepends its own group and the
//     policy text to a site's file:
//     https://developers.cloudflare.com/bots/additional-configurations/managed-robots-txt/
//   - Cloudflare Markdown for Agents, the converter that emits the
//     Content-Signal header:
//     https://developers.cloudflare.com/fundamentals/reference/markdown-for-agents/
//   - IETF AIPREF vocabulary: https://datatracker.ietf.org/doc/draft-ietf-aipref-vocab/
//   - IETF AIPREF attachment: https://datatracker.ietf.org/doc/draft-ietf-aipref-attach/
//   - Robots Exclusion Protocol: RFC 9309
//   - Sitemaps protocol 0.9: https://www.sitemaps.org/protocol.html
//   - llms.txt, v2 of August 2026, including the rel="alternate" and
//     rel="describedby" discovery links: https://llmstxt.org/
//   - HTTP content negotiation and the Accept field: RFC 9110 section 12
//   - The text/markdown media type: RFC 7763
package agentweb
