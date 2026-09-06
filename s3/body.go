// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"bytes"
	"crypto/md5" //nolint:gosec // Content-MD5 is the integrity header S3 defines
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"io"
	"os"
)

// Body is an object's content with the integrity values the store
// checks. Open is called once per attempt, so a retried upload re-reads
// the content rather than a spent reader.
type Body struct {
	Open func() (io.ReadCloser, error)
	// Size is sent as Content-Length.
	Size int64
	// SHA256 is the hex digest signed as x-amz-content-sha256. Empty
	// leaves the payload unsigned, which every provider accepts over TLS.
	SHA256 string
	// MD5 is the base64 digest sent as Content-MD5 when set. The store
	// refuses a body that does not match it, so a corrupted upload fails
	// instead of landing.
	MD5 string
}

// BytesBody wraps content held in memory, with both digests.
func BytesBody(b []byte) Body {
	sum := sha256.Sum256(b)
	m := md5.Sum(b) //nolint:gosec // Content-MD5
	return Body{
		Open:   func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil },
		Size:   int64(len(b)),
		SHA256: hex.EncodeToString(sum[:]),
		MD5:    base64.StdEncoding.EncodeToString(m[:]),
	}
}

// FileBody wraps a file, hashing it once now so a large file is read
// twice at most: once here and once per upload attempt.
func FileBody(path string) (Body, error) {
	f, err := os.Open(path)
	if err != nil {
		return Body{}, err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	m := md5.New() //nolint:gosec // Content-MD5
	n, err := io.Copy(io.MultiWriter(h, m), f)
	if err != nil {
		return Body{}, err
	}
	return Body{
		Open:   func() (io.ReadCloser, error) { return os.Open(path) },
		Size:   n,
		SHA256: hex.EncodeToString(h.Sum(nil)),
		MD5:    base64.StdEncoding.EncodeToString(m.Sum(nil)),
	}, nil
}

// ReadAll opens the body and reads it whole.
func (b Body) ReadAll() ([]byte, error) {
	r, err := b.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(r)
}
