// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package agentweb serves a site's public pages to crawlers and AI agents in
// the open conventions they read, starting with robots.txt carrying Content
// Signals usage preferences.
//
// The package holds no policy. Which usage preferences a site states,
// which crawlers it blocks, and whether it publishes the Content Signals
// Policy text are the site's configuration; the zero value of every option
// states nothing.
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
// ai-train=yes; a site that serves its own Markdown needs neither the
// converter nor its header.
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
package agentweb
