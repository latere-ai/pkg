// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Object is one listed or headed key.
type Object struct {
	Key  string
	Size int64
	// ETag as the provider sent it, quotes included where it sends them.
	ETag         string
	LastModified time.Time
	// ContentType is what the provider answered on GET or HEAD: the one
	// the upload carried, or the provider's default. A listing does not
	// carry it.
	ContentType string
}

// ListOptions selects one page of keys.
type ListOptions struct {
	// Prefix restricts the listing to keys that start with it.
	Prefix string
	// StartAfter continues a listing after this key. Pagination is the
	// last key of the previous page, which every provider orders the
	// same way; the continuation token is not used.
	StartAfter string
	// MaxKeys bounds the page. The provider's own limit, 1000, applies
	// when zero.
	MaxKeys int
	// Delimiter groups keys after the prefix up to the first delimiter
	// into Prefixes, the way a directory listing does.
	Delimiter string
}

// ListResult is one page of a listing. When Truncated, the next page
// starts after the last key of Objects, or of Prefixes when Objects is
// empty.
type ListResult struct {
	Objects   []Object
	Prefixes  []string
	Truncated bool
}

// PutObject writes key unconditionally and returns the ETag.
func (c *Client) PutObject(ctx context.Context, key string, body Body) (string, error) {
	resp, err := c.do(ctx, request{method: http.MethodPut, key: key, body: &body}, http.StatusOK)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	return resp.Header.Get("ETag"), nil
}

// CreateObject writes key only if it is absent (PUT with If-None-Match:
// *) and returns ErrPreconditionFailed when it is present, leaving the
// object untouched. It is the one primitive that linearizes writers on
// every provider; see the package documentation for why there is no
// If-Match.
func (c *Client) CreateObject(ctx context.Context, key string, body Body) (string, error) {
	resp, err := c.do(ctx, request{method: http.MethodPut, key: key, body: &body, headers: map[string]string{"If-None-Match": "*"}}, http.StatusOK)
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	return resp.Header.Get("ETag"), nil
}

// GetObject reads key. With ifNoneMatch set to an ETag the store answers
// ErrNotModified while the object still carries it. The caller closes
// the reader.
func (c *Client) GetObject(ctx context.Context, key, ifNoneMatch string) (io.ReadCloser, Object, error) {
	r := request{method: http.MethodGet, key: key}
	if ifNoneMatch != "" {
		r.headers = map[string]string{"If-None-Match": ifNoneMatch}
	}
	resp, err := c.do(ctx, r, http.StatusOK)
	if err != nil {
		return nil, Object{}, err
	}
	return resp.Body, objectFrom(key, resp), nil
}

// HeadObject reports the object's metadata without a body, or
// ErrNotFound.
func (c *Client) HeadObject(ctx context.Context, key string) (Object, error) {
	resp, err := c.do(ctx, request{method: http.MethodHead, key: key}, http.StatusOK)
	if err != nil {
		return Object{}, err
	}
	_ = resp.Body.Close()
	return objectFrom(key, resp), nil
}

func objectFrom(key string, resp *http.Response) Object {
	o := Object{Key: key, ETag: resp.Header.Get("ETag"), ContentType: resp.Header.Get("Content-Type")}
	if n, err := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64); err == nil {
		o.Size = n
	}
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		o.LastModified = t
	}
	return o
}

// DeleteObject removes key. A missing key is not an error: the key is
// gone either way.
func (c *Client) DeleteObject(ctx context.Context, key string) error {
	resp, err := c.do(ctx, request{method: http.MethodDelete, key: key}, http.StatusNoContent, http.StatusOK, http.StatusNotFound)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// ListObjects returns one page of keys in lexical order (ListObjectsV2).
func (c *Client) ListObjects(ctx context.Context, opts ListOptions) (ListResult, error) {
	q := url.Values{"list-type": {"2"}}
	if opts.Prefix != "" {
		q.Set("prefix", opts.Prefix)
	}
	if opts.StartAfter != "" {
		q.Set("start-after", opts.StartAfter)
	}
	if opts.MaxKeys > 0 {
		q.Set("max-keys", strconv.Itoa(opts.MaxKeys))
	}
	if opts.Delimiter != "" {
		q.Set("delimiter", opts.Delimiter)
	}
	resp, err := c.do(ctx, request{method: http.MethodGet, query: q}, http.StatusOK)
	if err != nil {
		return ListResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return ListResult{}, fmt.Errorf("s3: list: %w", err)
	}
	return parseListing(raw)
}

// listBucketResult is the ListObjectsV2 response document. The fake in
// s3test renders the same shape.
type listBucketResult struct {
	XMLName     xml.Name `xml:"ListBucketResult"`
	IsTruncated bool     `xml:"IsTruncated"`
	Contents    []struct {
		Key          string    `xml:"Key"`
		Size         int64     `xml:"Size"`
		ETag         string    `xml:"ETag"`
		LastModified time.Time `xml:"LastModified"`
	} `xml:"Contents"`
	CommonPrefixes []struct {
		Prefix string `xml:"Prefix"`
	} `xml:"CommonPrefixes"`
}

// parseListing decodes a ListObjectsV2 response body.
func parseListing(raw []byte) (ListResult, error) {
	var parsed listBucketResult
	if err := xml.Unmarshal(raw, &parsed); err != nil {
		return ListResult{}, fmt.Errorf("s3: list: %w", err)
	}
	res := ListResult{Truncated: parsed.IsTruncated}
	for _, c := range parsed.Contents {
		res.Objects = append(res.Objects, Object{Key: c.Key, Size: c.Size, ETag: c.ETag, LastModified: c.LastModified})
	}
	for _, p := range parsed.CommonPrefixes {
		res.Prefixes = append(res.Prefixes, p.Prefix)
	}
	return res, nil
}
