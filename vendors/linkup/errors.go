// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package linkup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The kinds of failure. Every *Error matches exactly one of them under
// errors.Is, decided by its status and, where one status covers several
// causes, by its code.
var (
	// ErrBadRequest is a request with a missing or malformed field: a 400
	// other than CodeNoResult, or a request this client refused before
	// sending it.
	ErrBadRequest = errors.New("linkup: bad request")
	// ErrNoResult is a search that found nothing, which the API answers as a
	// 400 with CodeNoResult.
	ErrNoResult = errors.New("linkup: no result")
	// ErrAuth is an API key the API did not accept: a 401 for a key that is
	// missing or invalid, a 403 for a key without access, or a 402, which
	// the API answers when it reads no key on the request.
	ErrAuth = errors.New("linkup: authentication failed")
	// ErrInsufficientCredit is a 429 for an account out of credit or a key
	// at its budget limit (CodeInsufficientCredit, CodeBudgetLimit). Another
	// call fails the same way until credit is added.
	ErrInsufficientCredit = errors.New("linkup: insufficient credit")
	// ErrRateLimited is any other 429: too many requests at a time. Another
	// call may succeed after Error.RetryAfter.
	ErrRateLimited = errors.New("linkup: rate limited")
	// ErrUpstream is a failure on the API's side: a 5xx, a status the API
	// does not document for a search, or a 200 whose body is not the shape
	// documented for the request's output type.
	ErrUpstream = errors.New("linkup: upstream failure")
)

// The error codes the API sends in error.code that decide a kind, and the
// one its own documentation shows for a refused field.
const (
	// CodeValidation is a 400 for a missing or malformed field; Details
	// names the fields.
	CodeValidation = "VALIDATION_ERROR"
	// CodeNoResult is a 400 for a search that found nothing.
	CodeNoResult = "SEARCH_QUERY_NO_RESULT"
	// CodeInsufficientCredit is a 429 for an account out of credit.
	CodeInsufficientCredit = "INSUFFICIENT_FUNDS_CREDITS"
	// CodeBudgetLimit is a 429 for a key at the budget limit set on it.
	CodeBudgetLimit = "EXCEED_BUDGET_LIMIT"
	// CodeTooManyRequests is a 429 for too many requests at a time.
	CodeTooManyRequests = "TOO_MANY_REQUESTS"
)

// Error is a search the API answered with a status other than 200. Code,
// Message and Details come from the body's error object when it has one;
// Message falls back to the body's text, then to the status text. Any
// occurrence of the client's API key in them is replaced with [redacted].
type Error struct {
	// StatusCode is the HTTP status of the answer.
	StatusCode int
	// Code is the API's name for the failure, such as CodeValidation. It is
	// empty when the body carries none.
	Code string
	// Message describes the failure.
	Message string
	// Details names the fields a refused request got wrong, one entry per
	// field. It is empty for a failure that is not about a field.
	Details []Detail
	// RetryAfter is the wait the Retry-After header asked for, and zero
	// when the answer carried none.
	RetryAfter time.Duration
}

// Detail is one field a refused request got wrong.
type Detail struct {
	// Field is the request field, by its name on the wire, such as
	// outputType.
	Field string
	// Message says what is wrong with it.
	Message string
}

// Error renders the status, the code, the message, the field details and
// the wait asked for.
func (e *Error) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "linkup: http %d", e.StatusCode)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	if len(e.Details) > 0 {
		parts := make([]string, 0, len(e.Details))
		for _, d := range e.Details {
			switch {
			case d.Field != "" && d.Message != "":
				parts = append(parts, d.Field+": "+d.Message)
			case d.Message != "":
				parts = append(parts, d.Message)
			case d.Field != "":
				parts = append(parts, d.Field)
			}
		}
		if len(parts) > 0 {
			b.WriteString(" (" + strings.Join(parts, "; ") + ")")
		}
	}
	if e.RetryAfter > 0 {
		b.WriteString(", retry after " + e.RetryAfter.String())
	}
	return b.String()
}

// Is reports whether target is the kind of this failure, so that
// errors.Is(err, ErrRateLimited) and the like answer for an *Error.
func (e *Error) Is(target error) bool {
	return target == e.kind()
}

// kind is the one failure kind of the error's status and code.
func (e *Error) kind() error {
	switch {
	case e.StatusCode == http.StatusBadRequest && e.Code == CodeNoResult:
		return ErrNoResult
	case e.StatusCode == http.StatusBadRequest:
		return ErrBadRequest
	case e.StatusCode == http.StatusUnauthorized, e.StatusCode == http.StatusPaymentRequired, e.StatusCode == http.StatusForbidden:
		return ErrAuth
	case e.StatusCode == http.StatusTooManyRequests && (e.Code == CodeInsufficientCredit || e.Code == CodeBudgetLimit):
		return ErrInsufficientCredit
	case e.StatusCode == http.StatusTooManyRequests:
		return ErrRateLimited
	default:
		return ErrUpstream
	}
}

// redacted replaces the API key wherever an error body echoes it.
const redacted = "[redacted]"

// maxMessage caps the length of a message lifted out of a body.
const maxMessage = 512

// now is the clock a Retry-After date is read against. Tests replace it.
var now = time.Now

// newError builds the Error of one answer outside 200 from its status, its
// headers and the bounded prefix of its body, with key replaced wherever the
// body holds it.
func newError(status int, header http.Header, body []byte, key string) *Error {
	e := &Error{StatusCode: status}
	e.Code, e.Message, e.Details = parseErrorBody(body)
	clean := func(s string) string {
		if key != "" {
			s = strings.ReplaceAll(s, key, redacted)
		}
		return truncate(strings.TrimSpace(s))
	}
	e.Code, e.Message = clean(e.Code), clean(e.Message)
	for i := range e.Details {
		e.Details[i] = Detail{Field: clean(e.Details[i].Field), Message: clean(e.Details[i].Message)}
	}
	if e.Message == "" {
		e.Message = http.StatusText(status)
	}
	if wait, ok := retryAfter(header.Get("Retry-After"), now()); ok {
		e.RetryAfter = wait
	}
	return e
}

// parseErrorBody reads the code, the message and the details out of a
// failure body. The API's envelope is {"statusCode", "error": {"code",
// "message", "details": [{"field", "message"}]}}. A body whose error is a
// string, or that carries only a top-level message, gives that text; a body
// that is not JSON, such as a gateway's page, is carried as text.
func parseErrorBody(body []byte) (code, message string, details []Detail) {
	var envelope struct {
		Error   json.RawMessage `json:"error"`
		Message string          `json:"message"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", string(body), nil
	}
	raw := bytes.TrimSpace(envelope.Error)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return "", envelope.Message, nil
	}
	switch raw[0] {
	case '{':
		var object struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Details []struct {
				Field   string `json:"field"`
				Message string `json:"message"`
			} `json:"details"`
		}
		if err := json.Unmarshal(raw, &object); err != nil {
			return "", compact(raw), nil
		}
		for _, d := range object.Details {
			details = append(details, Detail{Field: d.Field, Message: d.Message})
		}
		return object.Code, object.Message, details
	case '"':
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return "", compact(raw), nil
		}
		return "", text, nil
	default:
		return "", compact(raw), nil
	}
}

// compact renders a JSON value the shapes above do not cover as one line.
// It is called on a value json.Unmarshal already accepted, so it cannot
// fail.
func compact(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

// truncate caps a message at maxMessage bytes, on a rune boundary.
func truncate(s string) string {
	if len(s) <= maxMessage {
		return s
	}
	cut := maxMessage
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "..."
}

// retryAfter reads a Retry-After value: a count of seconds, or an HTTP date
// read against at. A date already past is a wait of zero; a value of
// neither form, or a negative count, is no wait.
func retryAfter(value string, at time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 {
			return 0, false
		}
		if seconds > int64(maxRetryAfter/time.Second) {
			return maxRetryAfter, true
		}
		return time.Duration(seconds) * time.Second, true
	}
	if when, err := http.ParseTime(value); err == nil {
		return max(when.Sub(at), 0), true
	}
	return 0, false
}

// maxRetryAfter is the longest wait a Retry-After count is read as. A count
// past it would overflow a time.Duration.
const maxRetryAfter = time.Duration(1<<63 - 1)
