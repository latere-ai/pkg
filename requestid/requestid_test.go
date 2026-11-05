// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package requestid_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"latere.ai/x/pkg/requestid"
)

func TestValid(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"empty", "", false},
		{"one byte", "a", true},
		{"typical", "req_abc-123.XYZ", true},
		{"range edges", "!~", true},
		{"max length", strings.Repeat("a", requestid.MaxLen), true},
		{"over max length", strings.Repeat("a", requestid.MaxLen+1), false},
		{"space", "a b", false},
		{"leading space", " a", false},
		{"tab", "a\tb", false},
		{"newline", "a\nb", false},
		{"carriage return", "a\rb", false},
		{"nul", "a\x00b", false},
		{"delete", "a\x7fb", false},
		{"non-ASCII", "café", false},
		{"invalid UTF-8", "a\xffb", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := requestid.Valid(tt.id); got != tt.want {
				t.Errorf("Valid(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	a, b := requestid.New(), requestid.New()
	if a == b {
		t.Errorf("two ids are equal: %q", a)
	}
	for _, id := range []string{a, b} {
		if !strings.HasPrefix(id, "req_") || len(id) == len("req_") {
			t.Errorf("New() = %q, want req_ prefix and a token", id)
		}
		if id != strings.ToLower(id) {
			t.Errorf("New() = %q, want lowercase", id)
		}
		if !requestid.Valid(id) {
			t.Errorf("New() = %q is not Valid", id)
		}
	}
}

func TestFromRequest(t *testing.T) {
	tests := []struct {
		name   string
		header []string
		keep   bool
	}{
		{"absent", nil, false},
		{"valid", []string{"client-id-1"}, true},
		{"empty", []string{""}, false},
		{"with space", []string{"a b"}, false},
		{"too long", []string{strings.Repeat("x", requestid.MaxLen+1)}, false},
		{"non-ASCII", []string{"idé"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, v := range tt.header {
				r.Header.Set(requestid.Header, v)
			}
			got := requestid.FromRequest(r)
			if tt.keep {
				if got != tt.header[0] {
					t.Errorf("FromRequest = %q, want %q", got, tt.header[0])
				}
				return
			}
			if !strings.HasPrefix(got, "req_") || !requestid.Valid(got) {
				t.Errorf("FromRequest = %q, want a minted id", got)
			}
		})
	}
}

func FuzzValid(f *testing.F) {
	for _, s := range []string{"", "a", "req_abc", "a b", "a\x00", "café", "\xff", "!~", "\x7f", strings.Repeat("a", requestid.MaxLen+1)} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if !requestid.Valid(s) {
			return
		}
		if len(s) == 0 || len(s) > requestid.MaxLen {
			t.Fatalf("Valid(%q) accepted length %d", s, len(s))
		}
		for i := range len(s) {
			if s[i] < 0x21 || s[i] > 0x7e {
				t.Fatalf("Valid(%q) accepted byte %#x", s, s[i])
			}
		}
	})
}
