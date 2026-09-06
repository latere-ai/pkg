// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"errors"
	"net/http"
	"strconv"
	"time"
)

// PresignGet returns a URL that reads key without a credential for
// expires from now. Whole seconds; the store refuses more than seven
// days.
func (c *Client) PresignGet(key string, expires time.Duration) (string, error) {
	return c.presign(http.MethodGet, key, expires, nil)
}

// PresignOption binds one more header into a presigned PUT's signature.
type PresignOption func(headers map[string]string)

// WithContentType binds Content-Type into the signature the way
// Content-Length is: the upload must carry exactly this type or the
// store refuses it. Empty binds nothing.
func WithContentType(contentType string) PresignOption {
	return func(headers map[string]string) {
		if contentType != "" {
			headers["Content-Type"] = contentType
		}
	}
}

// PresignPut returns a URL that writes key without a credential for
// expires from now, bound to a body of exactly contentLength bytes: the
// Content-Length header is in the signature, so a PUT of another size is
// refused by the store. That is what lets a service hand a client the
// URL for one upload it has already accounted for. [WithContentType]
// binds the type the same way, so the URL also pins what the object is.
func (c *Client) PresignPut(key string, expires time.Duration, contentLength int64, opts ...PresignOption) (string, error) {
	if contentLength < 0 {
		return "", errors.New("s3: presign put: content length is negative")
	}
	headers := map[string]string{"Content-Length": strconv.FormatInt(contentLength, 10)}
	for _, o := range opts {
		o(headers)
	}
	return c.presign(http.MethodPut, key, expires, headers)
}

func (c *Client) presign(method, key string, expires time.Duration, headers map[string]string) (string, error) {
	if key == "" {
		return "", errors.New("s3: presign: key is empty")
	}
	if expires < time.Second || expires > 7*24*time.Hour {
		return "", errors.New("s3: presign: expiry must be between one second and seven days")
	}
	req := &http.Request{Method: method, URL: c.objectURL(key, nil), Header: http.Header{}}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return c.signer.Presign(req, c.now(), expires), nil
}
