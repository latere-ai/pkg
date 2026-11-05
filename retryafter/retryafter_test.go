// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package retryafter

import (
	"math"
	"net/http"
	"strconv"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)

func TestParse(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  time.Duration
		ok    bool
	}{
		{"empty", "", 0, false},
		{"blank", "  \t", 0, false},
		{"zero", "0", 0, true},
		{"whole seconds", "120", 2 * time.Minute, true},
		{"surrounding space", " 7 ", 7 * time.Second, true},
		{"fractional", "1.5", 1500 * time.Millisecond, true},
		{"leading point", ".5", 500 * time.Millisecond, true},
		{"trailing point", "3.", 3 * time.Second, true},
		{"negative", "-1", 0, false},
		{"negative zero", "-0", 0, false},
		{"plus sign", "+5", 0, false},
		{"exponent", "1e3", 0, false},
		{"hex", "0x10", 0, false},
		{"two points", "1.2.3", 0, false},
		{"lone point", ".", 0, false},
		{"nan", "NaN", 0, false},
		{"infinity", "Inf", 0, false},
		{"signed infinity", "+Inf", 0, false},
		{"word", "soon", 0, false},
		{"largest count that fits", "9223372036", 9223372036 * time.Second, true},
		{"just beyond the duration range", "9223372037", math.MaxInt64, true},
		{"far beyond the duration range", "99999999999", math.MaxInt64, true},
		{"beyond float range", "1" + zeros(400), math.MaxInt64, true},
		{"tiny fraction", "0." + zeros(400) + "1", 0, true},
		{"date in the future", "Thu, 17 Sep 2026 12:00:30 GMT", 30 * time.Second, true},
		{"date now", "Thu, 17 Sep 2026 12:00:00 GMT", 0, true},
		{"date in the past", "Thu, 17 Sep 2026 11:00:00 GMT", 0, true},
		{"obsolete date form", "Thursday, 17-Sep-26 12:00:30 GMT", 30 * time.Second, true},
		{"asctime date form", "Thu Sep 17 12:00:30 2026", 30 * time.Second, true},
		{"date far ahead saturates", "Fri, 31 Dec 9999 23:59:59 GMT", math.MaxInt64, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := Parse(tt.value, now)
			if ok != tt.ok || got != tt.want {
				t.Errorf("Parse(%q) = %v, %v; want %v, %v", tt.value, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func zeros(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = '0'
	}
	return string(b)
}

func TestFormat(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{-time.Hour, "1"},
		{0, "1"},
		{time.Nanosecond, "1"},
		{999 * time.Millisecond, "1"},
		{time.Second, "1"},
		{time.Second + time.Nanosecond, "2"},
		{1500 * time.Millisecond, "2"},
		{2 * time.Second, "2"},
		{time.Minute, "60"},
		{math.MaxInt64, "9223372037"},
		{math.MinInt64, "1"},
	}
	for _, tt := range tests {
		if got := Format(tt.d); got != tt.want {
			t.Errorf("Format(%v) = %q, want %q", tt.d, got, tt.want)
		}
	}
}

func TestHeaderName(t *testing.T) {
	if Header != http.CanonicalHeaderKey(Header) {
		t.Errorf("Header %q is not in canonical form", Header)
	}
}

func TestFormatRoundTrip(t *testing.T) {
	for _, d := range []time.Duration{0, time.Millisecond, 1500 * time.Millisecond, 90 * time.Second, math.MaxInt64} {
		got, ok := Parse(Format(d), now)
		if !ok || got < d && d > 0 {
			t.Errorf("Parse(Format(%v)) = %v, %v; want at least the wait", d, got, ok)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"", " ", "0", "120", "-5", "1.5", ".5", "1e3", "NaN", "Inf", "+Inf", "0x1p3",
		"99999999999999999999", "9223372037", "1" + zeros(400),
		"Thu, 17 Sep 2026 12:00:30 GMT", "Thursday, 17-Sep-26 12:00:30 GMT", "Fri, 31 Dec 9999 23:59:59 GMT",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got, ok := Parse(value, now)
		if got < 0 {
			t.Fatalf("Parse(%q) = %v, a negative wait", value, got)
		}
		if !ok && got != 0 {
			t.Fatalf("Parse(%q) = %v, false; a refused value has no wait", value, got)
		}
	})
}

func FuzzFormat(f *testing.F) {
	for _, seed := range []int64{math.MinInt64, -1, 0, 1, int64(time.Second), int64(time.Second) + 1, math.MaxInt64} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, ns int64) {
		d := time.Duration(ns)
		s := Format(d)
		seconds, err := strconv.ParseInt(s, 10, 64)
		if err != nil || seconds < 1 {
			t.Fatalf("Format(%v) = %q, want whole seconds of at least 1", d, s)
		}
		if time.Duration(seconds) < d/time.Second {
			t.Fatalf("Format(%v) = %q, shorter than the wait", d, s)
		}
		want := time.Duration(math.MaxInt64)
		if seconds <= math.MaxInt64/int64(time.Second) {
			want = time.Duration(seconds) * time.Second
		}
		if got, ok := Parse(s, now); !ok || got != want {
			t.Fatalf("Parse(Format(%v)) = %v, %v; want %v", d, got, ok, want)
		}
	})
}
