// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import "net/http"

// SubstituteHTTPRequest applies m to an outbound *http.Request bound for host,
// rewriting header values and the raw query string in place, and reports
// whether anything changed. The body is never read or buffered (SSE-safe).
//
// Scope: substitution covers header values and the query string, which is
// where verbatim-transmitted credentials ride (Authorization, x-api-key,
// ?api_key=). It intentionally does not rewrite the URL path, whose
// re-escaping on write could corrupt a raw secret; path-embedded secrets are
// out of scope. host must be the CONNECT/SNI destination, not a value read
// from the request.
func SubstituteHTTPRequest(host string, req *http.Request, m *Map) bool {
	if m.Empty() || req == nil {
		return false
	}
	changed := false
	if req.URL != nil && req.URL.RawQuery != "" {
		if v, ok := m.SubstituteValue(host, req.URL.RawQuery); ok {
			req.URL.RawQuery = v
			changed = true
		}
	}
	for name, vals := range req.Header {
		for i, v := range vals {
			if nv, ok := m.SubstituteValue(host, v); ok {
				req.Header[name][i] = nv
				changed = true
			}
		}
	}
	return changed
}
