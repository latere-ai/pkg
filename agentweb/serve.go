// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// DefaultCacheControl is the Cache-Control the document handlers send when a
// site configures none.
//
// A response without Cache-Control leaves freshness to whatever sits in
// front of the site: a CDN applies its own default, which can hold a
// replaced robots.txt or llms.txt for hours after a deploy, and a site that
// is not behind one gets whatever each client guesses. Five minutes bounds
// how long a deploy takes to show, while a CDN still answers repeated
// fetches of the larger documents (a sitemap, llms-full.txt) without
// reaching the origin each time. Revalidating after that is cheap: the
// rendered documents carry a strong ETag.
//
// It is not no-cache because freshness at the edge does not reach crawlers
// any sooner: RFC 9309 lets a crawler keep its own copy of robots.txt for up
// to 24 hours.
const DefaultCacheControl = "public, max-age=300"

// cacheControl returns the Cache-Control value a handler sends: the site's
// value, or [DefaultCacheControl] when it set none. A value that could
// split the header is refused, so a bad configuration fails at startup.
func cacheControl(v string) (string, error) {
	if v == "" {
		return DefaultCacheControl, nil
	}
	if strings.ContainsAny(v, "\r\n\x00") {
		return "", fmt.Errorf("agentweb: cache control %q contains a line break or NUL", v)
	}
	return v, nil
}

// staticHandler serves a document rendered once at construction.
//
// The strong ETag is the document's digest, so a crawler that revalidates
// gets a 304 without a body, and http.ServeContent answers HEAD and Range
// requests. cc is the Cache-Control value, already resolved by
// [cacheControl].
func staticHandler(body []byte, contentType, cc string) http.Handler {
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowRead(w, r) {
			return
		}
		h := w.Header()
		h.Set("Content-Type", contentType)
		h.Set("Cache-Control", cc)
		h.Set("ETag", etag)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
	})
}

// allowRead answers any method other than GET and HEAD with 405 and reports
// whether the request may proceed.
func allowRead(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return true
	}
	w.Header().Set("Allow", "GET, HEAD")
	http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	return false
}
