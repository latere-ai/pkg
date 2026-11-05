// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package ulid

import (
	"strings"
	"sync"
	"testing"
	"time"
)

func frozen(t time.Time) func() time.Time { return func() time.Time { return t } }

func TestOrderWithinOneMillisecond(t *testing.T) {
	g := &Generator{Now: frozen(time.UnixMilli(1_700_000_000_123))}
	prev := g.New("fil_")
	for range 10_000 {
		next := g.New("fil_")
		if next <= prev {
			t.Fatalf("%q does not follow %q", next, prev)
		}
		prev = next
	}
}

func TestOrderUpper(t *testing.T) {
	g := &Generator{Now: frozen(time.UnixMilli(5)), Upper: true}
	prev := g.New("")
	for range 1000 {
		next := g.New("")
		if next <= prev {
			t.Fatalf("%q does not follow %q", next, prev)
		}
		prev = next
	}
}

func TestOrderAcrossMilliseconds(t *testing.T) {
	now := time.UnixMilli(1000)
	g := &Generator{Now: func() time.Time { return now }}
	prev := g.New("x_")
	for range 100 {
		now = now.Add(time.Millisecond)
		next := g.New("x_")
		if next <= prev {
			t.Fatalf("%q does not follow %q", next, prev)
		}
		prev = next
	}
}

func TestClockGoesBackward(t *testing.T) {
	now := time.UnixMilli(5000)
	g := &Generator{Now: func() time.Time { return now }}
	a := g.New("a_")
	now = time.UnixMilli(1000)
	b := g.New("a_")
	if b <= a {
		t.Fatalf("%q does not follow %q after the clock stepped back", b, a)
	}
	got, ok := Time(b)
	if !ok || got.UnixMilli() != 5000 {
		t.Fatalf("Time(%q) = %v, %v; want the last timestamp 5000", b, got, ok)
	}
}

func TestCarryAndWrap(t *testing.T) {
	g := &Generator{Now: frozen(time.UnixMilli(7))}
	g.New("")
	g.tail = [10]byte{0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff}
	g.New("")
	if g.tail != [10]byte{0, 0, 0, 0, 0, 0, 0, 1, 0, 0} {
		t.Fatalf("carry: tail = %v", g.tail)
	}
	g.tail = [10]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	g.New("")
	if g.tail != [10]byte{} {
		t.Fatalf("overflow should wrap to zero: tail = %v", g.tail)
	}
}

func TestConcurrent(t *testing.T) {
	g := &Generator{}
	const workers, each = 8, 500
	var mu sync.Mutex
	seen := make(map[string]bool, workers*each)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			ids := make([]string, each)
			for i := range ids {
				ids[i] = g.New("c_")
			}
			mu.Lock()
			defer mu.Unlock()
			for _, id := range ids {
				if seen[id] {
					t.Errorf("duplicate %q", id)
				}
				seen[id] = true
			}
		})
	}
	wg.Wait()
	if len(seen) != workers*each {
		t.Fatalf("got %d unique ids, want %d", len(seen), workers*each)
	}
}

func TestCaseRoundTrip(t *testing.T) {
	now := time.UnixMilli(1_700_000_000_456)
	lower := (&Generator{Now: frozen(now)}).New("fil_")
	upper := (&Generator{Now: frozen(now), Upper: true}).New("FIL_")
	if lower != strings.ToLower(lower) || upper != strings.ToUpper(upper) {
		t.Fatalf("case: %q %q", lower, upper)
	}
	for _, c := range []struct{ prefix, id string }{
		{"fil_", lower}, {"FIL_", upper},
		{"fil_", "fil_" + strings.ToUpper(lower[4:])},
		{"FIL_", "FIL_" + strings.ToLower(upper[4:])},
	} {
		if !Valid(c.prefix, c.id) {
			t.Errorf("Valid(%q, %q) = false", c.prefix, c.id)
		}
		if got, ok := Time(c.id); !ok || got.UnixMilli() != now.UnixMilli() {
			t.Errorf("Time(%q) = %v, %v", c.id, got, ok)
		}
	}
}

func TestPrefixVerbatim(t *testing.T) {
	g := &Generator{}
	if id := g.New(""); len(id) != 26 || !Valid("", id) {
		t.Errorf("empty prefix: %q", id)
	}
	if id := g.New("a-b:"); !strings.HasPrefix(id, "a-b:") || len(id) != 30 {
		t.Errorf("prefix not kept verbatim: %q", id)
	}
}

func TestDefaultNew(t *testing.T) {
	before := time.Now().UnixMilli()
	id := New("def_")
	after := time.Now().UnixMilli()
	if !Valid("def_", id) || id != strings.ToLower(id) {
		t.Fatalf("New = %q", id)
	}
	got, _ := Time(id)
	if ms := got.UnixMilli(); ms < before || ms > after {
		t.Fatalf("time %d outside [%d, %d]", ms, before, after)
	}
}

func TestTimeMatchesClock(t *testing.T) {
	want := time.UnixMilli(1_700_000_000_999)
	for _, upper := range []bool{false, true} {
		id := (&Generator{Now: frozen(want), Upper: upper}).New("p_")
		got, ok := Time(id)
		if !ok || !got.Equal(want) {
			t.Errorf("upper=%v: Time = %v, %v; want %v", upper, got, ok, want)
		}
	}
}

func TestVectors(t *testing.T) {
	zero := strings.Repeat("0", 26)
	max := "7" + strings.Repeat("Z", 25)
	if got, ok := Time(zero); !ok || got.UnixMilli() != 0 {
		t.Errorf("zero: %v %v", got, ok)
	}
	if got, ok := Time(max); !ok || got.UnixMilli() != 1<<48-1 {
		t.Errorf("max: %v %v", got, ok)
	}
	if !Valid("", zero) || !Valid("", max) || !Valid("", strings.ToLower(max)) {
		t.Error("bounds should be valid")
	}
	// The spec example: 01ARZ3NDEKTSV4RRFFQ69G5FAV is 1469922850259 ms.
	if got, ok := Time("01ARZ3NDEKTSV4RRFFQ69G5FAV"); !ok || got.UnixMilli() != 1469922850259 {
		t.Errorf("spec example: %v %v", got, ok)
	}
	// A timestamp of 1 ms.
	if got, ok := Time(strings.Repeat("0", 9) + "1" + strings.Repeat("0", 16)); !ok || got.UnixMilli() != 1 {
		t.Errorf("one ms: %v %v", got, ok)
	}
	// Minting the vector's time reproduces its encoding.
	g := &Generator{Now: frozen(time.UnixMilli(1469922850259)), Upper: true}
	if id := g.New(""); !strings.HasPrefix(id, "01ARZ3NDEK") {
		t.Errorf("encoding: %q", id)
	}
}

func TestInvalid(t *testing.T) {
	good := strings.Repeat("0", 26)
	for name, c := range map[string]struct{ prefix, id string }{
		"wrong prefix":   {"fil_", "obj_" + good},
		"no prefix":      {"fil_", good},
		"short":          {"", good[1:]},
		"long":           {"", good + "0"},
		"overflow first": {"", "8" + good[1:]},
		"letter I":       {"", "I" + good[1:]},
		"letter L":       {"", "0L" + good[2:]},
		"letter O":       {"", "0O" + good[2:]},
		"letter U":       {"", "0U" + good[2:]},
		"punctuation":    {"", "0_" + good[2:]},
		"non ascii":      {"", "0é" + good[3:]},
		"empty":          {"", ""},
	} {
		if Valid(c.prefix, c.id) {
			t.Errorf("%s: Valid(%q, %q) = true", name, c.prefix, c.id)
		}
	}
	for _, id := range []string{"", "short", "8" + good[1:], "x_" + "8" + good[1:], good + "!"} {
		if _, ok := Time(id); ok {
			t.Errorf("Time(%q) ok", id)
		}
	}
}

func FuzzValid(f *testing.F) {
	for _, s := range [][2]string{
		{"fil_", "fil_01hq3k7z8y9abcdefghjkmnpqr"},
		{"", "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"},
		{"", "00000000000000000000000000"},
		{"x", "8" + strings.Repeat("0", 25)},
		{"a_", ""},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, prefix, id string) {
		if !Valid(prefix, id) {
			return
		}
		if !strings.HasPrefix(id, prefix) {
			t.Fatalf("Valid(%q, %q) without the prefix", prefix, id)
		}
		ts, ok := Time(id)
		if !ok {
			t.Fatalf("Valid id %q has no Time", id)
		}
		if ms := ts.UnixMilli(); ms < 0 || ms >= 1<<48 {
			t.Fatalf("Time(%q) = %d out of range", id, ms)
		}
		if !Valid(prefix, id[:len(prefix)]+strings.ToUpper(id[len(prefix):])) ||
			!Valid(prefix, id[:len(prefix)]+strings.ToLower(id[len(prefix):])) {
			t.Fatalf("case changes the validity of %q", id)
		}
	})
}

func FuzzTime(f *testing.F) {
	for _, s := range []string{
		"", "fil_01hq3k7z8y9abcdefghjkmnpqr", "00000000000000000000000000",
		"7ZZZZZZZZZZZZZZZZZZZZZZZZZ", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "01ARZ3NDEKTSV4RRFFQ69G5FAV",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, id string) {
		ts, ok := Time(id)
		if !ok {
			return
		}
		if ms := ts.UnixMilli(); ms < 0 || ms >= 1<<48 {
			t.Fatalf("Time(%q) = %d out of range", id, ms)
		}
		if !Valid(id[:len(id)-ulidLen], id) {
			t.Fatalf("Time accepted %q but Valid rejects it", id)
		}
	})
}
