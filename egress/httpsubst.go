// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"bytes"
	"context"
	"io"
	"mime"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
)

// DefaultMaxBodyBytes is the largest request body
// [SubstituteHTTPRequestContext] reads for substitution when no
// [WithMaxBodyBytes] option is given.
const DefaultMaxBodyBytes = 64 << 10

// SubstituteOption adjusts one [SubstituteHTTPRequestContext] call.
type SubstituteOption func(*substituteOptions)

type substituteOptions struct {
	maxBody int64
}

// WithMaxBodyBytes sets the largest Content-Length a body may declare and
// still be read for substitution. Zero or negative disables body
// substitution for the call.
func WithMaxBodyBytes(n int64) SubstituteOption {
	return func(o *substituteOptions) { o.maxBody = n }
}

// SubstituteHTTPRequest applies m to an outbound *http.Request bound for host,
// rewriting header values and the raw query string in place, and reports
// whether anything changed. The body is never read or buffered (SSE-safe).
//
// Scope: substitution covers header values and the query string, which is
// where verbatim-transmitted credentials ride (Authorization, x-api-key,
// ?api_key=). It intentionally does not rewrite the URL path, whose
// re-escaping on write could corrupt a raw secret; path-embedded secrets are
// out of scope. The framing and hop-by-hop headers listed in the package
// documentation are never rewritten. host must be the CONNECT/SNI
// destination, not a value read from the request.
//
// Only static entries take part: an entry with [Entry.Resolve] set is
// skipped and its placeholder passes through unchanged. Use
// [SubstituteHTTPRequestContext] when the map may hold dynamic entries or
// entries with [Entry.SubstituteBody].
func SubstituteHTTPRequest(host string, req *http.Request, m *Map) bool {
	changed, _ := substituteRequest(context.Background(), host, req, m, modeStaticOnly, substituteOptions{})
	return changed
}

// SubstituteHTTPRequestContext is [SubstituteHTTPRequest] for maps that may
// hold dynamic entries, plus body substitution for entries that opted in.
//
// The body is read only when the request declares a Content-Length of at
// most the limit (default [DefaultMaxBodyBytes]) and a Content-Type of JSON
// (application/json or a +json suffix), application/x-www-form-urlencoded,
// or text/*. Then every placeholder of an entry with [Entry.SubstituteBody]
// set is replaced and the body and Content-Length are rewritten. A body with
// no Content-Length, a chunked body, a larger body, or any other media type
// is left untouched, so a streaming request or an upload is never buffered.
//
// Every resolver is run at most once per call. On any error the request is
// returned exactly as given, so a caller can fail the request instead of
// sending it with a placeholder that was meant to be replaced.
func SubstituteHTTPRequestContext(ctx context.Context, host string, req *http.Request, m *Map, opts ...SubstituteOption) (bool, error) {
	o := substituteOptions{maxBody: DefaultMaxBodyBytes}
	for _, opt := range opts {
		opt(&o)
	}
	return substituteRequest(ctx, host, req, m, 0, o)
}

// substituteRequest computes every rewrite first and applies them only when
// all succeeded, which is what makes the error contract hold.
func substituteRequest(ctx context.Context, host string, req *http.Request, m *Map, mode subMode, o substituteOptions) (bool, error) {
	if m.Empty() || req == nil {
		return false, nil
	}
	cache := resolved{}

	var query string
	queryChanged := false
	if req.URL != nil && req.URL.RawQuery != "" {
		v, ok, err := m.substitute(ctx, host, req.URL.RawQuery, mode, cache)
		if err != nil {
			return false, err
		}
		query, queryChanged = v, ok
	}

	type headerEdit struct {
		name string
		i    int
		v    string
	}
	var edits []headerEdit
	for name, vals := range req.Header {
		if !substitutableHeader(name) {
			continue
		}
		for i, v := range vals {
			nv, ok, err := m.substitute(ctx, host, v, mode, cache)
			if err != nil {
				return false, err
			}
			if ok {
				edits = append(edits, headerEdit{name, i, nv})
			}
		}
	}

	var body []byte
	bodyChanged := false
	if mode&modeStaticOnly == 0 {
		orig, ok := readSubstitutableBody(req, o.maxBody)
		if ok {
			v, changed, err := m.substitute(ctx, host, string(orig), mode|modeBodyOnly, cache)
			if err != nil {
				return false, err
			}
			if changed {
				body, bodyChanged = []byte(v), true
			}
		}
	}

	if queryChanged {
		req.URL.RawQuery = query
	}
	for _, e := range edits {
		req.Header[e.name][e.i] = e.v
	}
	if bodyChanged {
		setBody(req, body)
	}
	return queryChanged || len(edits) > 0 || bodyChanged, nil
}

// substitutableHeader reports whether a header may carry a placeholder. The
// framing and hop-by-hop set is excluded because a rewrite there changes how
// the request is parsed rather than what it authenticates as, and
// X-Forwarded-* because those are the proxy's own annotations.
func substitutableHeader(name string) bool {
	switch textproto.CanonicalMIMEHeaderKey(name) {
	case "Content-Length", "Transfer-Encoding", "Te", "Trailer",
		"Connection", "Keep-Alive", "Upgrade", "Proxy-Connection",
		"Proxy-Authorization":
		return false
	}
	return !hasPrefixFold(name, "X-Forwarded-")
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// readSubstitutableBody returns the body bytes when the body rule admits the
// request. It always leaves req readable: when the body was read it is put
// back as an in-memory reader, whether or not it is later rewritten.
func readSubstitutableBody(req *http.Request, maxBody int64) ([]byte, bool) {
	if req.Body == nil || req.Body == http.NoBody || maxBody <= 0 {
		return nil, false
	}
	n := req.ContentLength
	if n <= 0 || n > maxBody || !substitutableMediaType(req.Header.Get("Content-Type")) {
		return nil, false
	}
	buf, err := io.ReadAll(io.LimitReader(req.Body, n))
	// What was read goes back in front of whatever remains, so the caller
	// sees the body exactly as the wire would have delivered it, including
	// after a short or failing read.
	req.Body = readCloser{io.MultiReader(bytes.NewReader(buf), req.Body), req.Body}
	if err != nil || int64(len(buf)) != n {
		return nil, false
	}
	return buf, true
}

// readCloser reads from Reader and closes the original body.
type readCloser struct {
	io.Reader
	io.Closer
}

// substitutableMediaType admits the textual types a credential can ride in.
func substitutableMediaType(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	switch {
	case mt == "application/json", strings.HasSuffix(mt, "+json"):
		return true
	case mt == "application/x-www-form-urlencoded":
		return true
	case strings.HasPrefix(mt, "text/"):
		return true
	}
	return false
}

// setBody installs the rewritten body and keeps the framing consistent: the
// length changes with the secret, so Content-Length follows it, and GetBody
// lets the transport replay the body on a redirect or a retried connection.
func setBody(req *http.Request, body []byte) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	req.ContentLength = int64(len(body))
	if _, ok := req.Header["Content-Length"]; ok {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}
}
