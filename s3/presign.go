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

// PresignPut returns a URL that writes key without a credential for
// expires from now, bound to a body of exactly contentLength bytes: the
// Content-Length header is in the signature, so a PUT of another size is
// refused by the store. That is what lets a service hand a client the
// URL for one upload it has already accounted for.
func (c *Client) PresignPut(key string, expires time.Duration, contentLength int64) (string, error) {
	if contentLength < 0 {
		return "", errors.New("s3: presign put: content length is negative")
	}
	return c.presign(http.MethodPut, key, expires, map[string]string{"Content-Length": strconv.FormatInt(contentLength, 10)})
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
