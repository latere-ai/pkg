// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package agentweb

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"
)

// staticHandler serves a document rendered once at construction.
//
// The strong ETag is the document's digest, so a crawler that revalidates
// gets a 304 without a body, and http.ServeContent answers HEAD and Range
// requests. Caching policy (Cache-Control) is left to the site, which knows
// how often it deploys.
func staticHandler(body []byte, contentType string) http.Handler {
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:16]) + `"`
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowRead(w, r) {
			return
		}
		h := w.Header()
		h.Set("Content-Type", contentType)
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
