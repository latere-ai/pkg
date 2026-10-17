// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pricelist

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// TestParsePriceRoundsHalfEvenToTheMicroUnit: a price, USD per token in a
// decimal longer than a float64 holds, becomes micro-USD per million tokens
// exactly, rounded half-even, and a price that is zero or rounds to zero is
// no fixed price.
func TestParsePriceRoundsHalfEvenToTheMicroUnit(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want int64
		ok   bool
	}{
		{"0.0000025", 2_500_000, true},
		{"0.000003", 3_000_000, true},
		{"0.000004", 4_000_000, true},
		{"0.000000125", 125_000, true},
		{" 0.000000125 ", 125_000, true},
		{"1.25e-7", 125_000, true},
		{"0.000000123456789", 123_457, true},         // 123456.789 rounds up
		{"0.0000001234565", 123_456, true},           // exactly half, to the even 123456
		{"0.0000001234575", 123_458, true},           // exactly half, to the even 123458
		{"0.00000012345650000000001", 123_457, true}, // a hair above half rounds up
		{"0.0000000000015", 2, true},                 // 1.5 to the even 2
		{"0.0000000000025", 2, true},                 // 2.5 to the even 2
		{"3e-7", 300_000, true},
		{"1.5E-06", 1_500_000, true},
		{".000001", 1_000_000, true},
		{"0.0000000000005", 0, false},  // half of a micro-unit, to the even 0
		{"0.00000000000049", 0, false}, // below half of a micro-unit
		{"0", 0, false},
		{"-1", 0, false}, // the list's mark of a price set per request
		{"-0.000004", 0, false},
		{"", 0, false},
		{"free", 0, false},
		{"abc", 0, false},
		{"1e999", 0, false},       // an exponent past two digits is refused before any arithmetic
		{"99999999999", 0, false}, // past what int64 micro-units hold
	} {
		got, ok := ParsePrice(tc.in).PerMillion()
		if ok != tc.ok || (ok && got != tc.want) {
			t.Errorf("ParsePrice(%q).PerMillion() = %d %v, want %d %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestParsePriceTellsZeroAndAbsenceApart: an exact zero, a price that only
// rounds to zero, a price that is no decimal and a price not stated are four
// different answers, which a reader that treats a stated zero as free needs.
func TestParsePriceTellsZeroAndAbsenceApart(t *testing.T) {
	for _, tc := range []struct {
		in     string
		stated bool
		zero   bool
	}{
		{"", false, false},
		{"   ", false, false},
		{"0", true, true},
		{"0.000000", true, true},
		{"0e5", true, true},
		{"0.0000000000004", true, false}, // rounds to zero, is not zero
		{"-1", true, false},
		{"not a price", true, false},
		{"0.000001", true, false},
	} {
		p := ParsePrice(tc.in)
		if p.Stated() != tc.stated || p.Zero() != tc.zero {
			t.Errorf("ParsePrice(%q): Stated %v Zero %v, want %v %v", tc.in, p.Stated(), p.Zero(), tc.stated, tc.zero)
		}
		if _, ok := p.PerMillion(); ok && (p.Zero() || !p.Stated()) {
			t.Errorf("ParsePrice(%q) is a fixed price and also zero or unstated", tc.in)
		}
	}
	if (Price{}).Stated() {
		t.Error("the zero Price reads as stated")
	}
}

// TestPriceUnmarshalJSON: a price is a JSON string or null, and any other
// JSON value fails the decode.
func TestPriceUnmarshalJSON(t *testing.T) {
	var p Price
	if err := json.Unmarshal([]byte(`"0.000002"`), &p); err != nil {
		t.Fatal(err)
	}
	if got, ok := p.PerMillion(); !ok || got != 2_000_000 {
		t.Fatalf("a string price read as %d %v", got, ok)
	}
	if err := json.Unmarshal([]byte(`null`), &p); err != nil {
		t.Fatal(err)
	}
	if p.Stated() {
		t.Fatal("null read as a stated price")
	}
	for _, bad := range []string{`0.000002`, `true`, `{}`, `["0.1"]`} {
		if err := json.Unmarshal([]byte(bad), &p); err == nil {
			t.Errorf("%s decoded as a price", bad)
		}
	}
}

// FuzzParsePrice holds the parser to its contract on any input: a fixed
// price is at least one micro-unit, is within half a micro-unit of the exact
// value, and is neither zero nor unstated; only a blank string is unstated.
func FuzzParsePrice(f *testing.F) {
	for _, s := range []string{"0.000000125", "1.25e-7", "0", "", " ", "-1", "free", "1e999", "99999999999", "0.0000001234565", "9e-99", ".5", "5."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		p := ParsePrice(s)
		if p.Stated() != (strings.TrimSpace(s) != "") {
			t.Fatalf("ParsePrice(%q).Stated() = %v", s, p.Stated())
		}
		micro, ok := p.PerMillion()
		if !ok {
			return
		}
		if micro <= 0 || p.Zero() {
			t.Fatalf("ParsePrice(%q) = %d, a fixed price that is not above zero", s, micro)
		}
		exact, parsed := new(big.Rat).SetString(strings.TrimSpace(s))
		if !parsed {
			t.Fatalf("ParsePrice(%q) priced a string big.Rat cannot read", s)
		}
		exact.Mul(exact, microPerMillion)
		diff := new(big.Rat).Sub(exact, new(big.Rat).SetInt64(micro))
		if diff.Abs(diff).Cmp(big.NewRat(1, 2)) > 0 {
			t.Fatalf("ParsePrice(%q) = %d, more than half a micro-unit from %s", s, micro, exact.FloatString(6))
		}
	})
}
