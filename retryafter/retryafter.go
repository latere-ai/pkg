// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package retryafter reads and writes the HTTP Retry-After header.
//
// Parse accepts both forms a server may send, a count of seconds and an HTTP
// date, and never returns a negative wait: a count too large for a
// time.Duration saturates at the largest duration instead of overflowing, and
// a date already past is no wait at all. Format writes a wait the way servers
// conventionally do, in whole seconds rounded up and never less than one.
package retryafter

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Header is the name of the response header that asks a client to wait before
// sending the request again.
const Header = "Retry-After"

// Parse reads the value of a Retry-After header as a wait, measured from now
// for the date form. Surrounding space is ignored.
//
// A non-negative decimal count of seconds, whole or fractional, is that wait;
// a count beyond the largest time.Duration saturates at it. An HTTP date is
// the time from now to it, and a date already past is a wait of zero. An empty
// value, a negative count, an exponent form, NaN, infinity, or anything else
// reports false with a wait of zero.
func Parse(value string, now time.Time) (time.Duration, bool) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, false
	}
	if isDecimal(value) {
		seconds, err := strconv.ParseFloat(value, 64)
		if err != nil && !errors.Is(err, strconv.ErrRange) {
			return 0, false
		}
		scaled := seconds * float64(time.Second)
		if scaled >= math.MaxInt64 {
			return math.MaxInt64, true
		}
		return time.Duration(scaled), true
	}
	if deadline, err := http.ParseTime(value); err == nil {
		return max(deadline.Sub(now), 0), true
	}
	return 0, false
}

// isDecimal reports whether s is digits with at most one decimal point and at
// least one digit: the shape of a count of seconds, with no sign, exponent or
// name such as inf.
func isDecimal(s string) bool {
	digits, points := 0, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c == '.':
			points++
		default:
			return false
		}
	}
	return digits > 0 && points <= 1
}

// Format returns the header value for a wait: whole seconds, rounded up and
// never less than 1, so a client never retries before the wait is over and a
// zero or negative wait still names a pause.
func Format(d time.Duration) string {
	seconds := int64(math.Ceil(d.Seconds()))
	return strconv.FormatInt(max(seconds, 1), 10)
}
