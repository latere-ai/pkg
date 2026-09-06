// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package s3

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Sentinel outcomes a caller branches on. Each wraps into the [*Error]
// the response produced, so errors.Is matches the sentinel and errors.As
// reaches the status and code.
var (
	// ErrNotFound is a 404: the key does not exist.
	ErrNotFound = errors.New("s3: object not found")
	// ErrPreconditionFailed is a 412: on CreateObject, the key existed.
	ErrPreconditionFailed = errors.New("s3: precondition failed")
	// ErrNotModified is a 304 on a GetObject with If-None-Match.
	ErrNotModified = errors.New("s3: not modified")
)

// Error is a response the store refused. Code and Message come from the
// XML error body when the store sent one.
type Error struct {
	Status  int
	Code    string
	Message string
	// Body is what the store sent when it was not an XML error document,
	// truncated to 4 KiB.
	Body string
}

func (e *Error) Error() string {
	switch {
	case e.Code != "":
		return fmt.Sprintf("s3: %d %s: %s", e.Status, e.Code, e.Message)
	case e.Body != "":
		return fmt.Sprintf("s3: %d: %s", e.Status, e.Body)
	}
	return fmt.Sprintf("s3: %d", e.Status)
}

// Is maps the three statuses to their sentinels.
func (e *Error) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Status == http.StatusNotFound
	case ErrPreconditionFailed:
		return e.Status == http.StatusPreconditionFailed
	case ErrNotModified:
		return e.Status == http.StatusNotModified
	}
	return false
}

// responseError reads a refused response into an Error.
func responseError(resp *http.Response) *Error {
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return parseError(resp.StatusCode, raw)
}

// parseError builds the Error for a status and the body the store sent.
func parseError(status int, raw []byte) *Error {
	e := &Error{Status: status}
	var body struct {
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	if xml.Unmarshal(raw, &body) == nil && body.Code != "" {
		e.Code, e.Message = body.Code, body.Message
		return e
	}
	e.Body = strings.TrimSpace(string(raw))
	return e
}
