package bearer

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	cases := []struct {
		in    string
		token string
		ok    bool
	}{
		{"Bearer abc", "abc", true},
		{"bearer abc", "abc", true},
		{"BEARER abc", "abc", true},
		{"Bearer   abc  ", "abc", true},
		{"  Bearer abc", "abc", true},
		{"Bearer a b", "a b", true},
		{"", "", false},
		{"Bearer", "", false},
		{"Bearer ", "", false},
		{"Basic abc", "", false},
		{"Bearerabc", "", false},
		{"abc", "", false},
	}
	for _, c := range cases {
		token, ok := Parse(c.in)
		if token != c.token || ok != c.ok {
			t.Errorf("Parse(%q) = %q, %v; want %q, %v", c.in, token, ok, c.token, c.ok)
		}
	}
}

func TestFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if _, ok := FromRequest(r); ok {
		t.Fatal("no header reported ok")
	}
	r.Header.Set("Authorization", "bearer tok")
	if token, ok := FromRequest(r); !ok || token != "tok" {
		t.Fatalf("FromRequest = %q, %v", token, ok)
	}
}

func TestEqual(t *testing.T) {
	if !Equal("abc", "abc") {
		t.Fatal("equal tokens reported unequal")
	}
	if Equal("abc", "abd") || Equal("abc", "ab") || Equal("", "a") {
		t.Fatal("unequal tokens reported equal")
	}
	if !Equal("", "") {
		t.Fatal("two empty strings are equal; callers guard the empty secret")
	}
}

func FuzzParse(f *testing.F) {
	f.Add("Bearer abc")
	f.Add("bearer\tabc")
	f.Add(" Basic x")
	f.Fuzz(func(t *testing.T, in string) {
		token, ok := Parse(in)
		if !ok && token != "" {
			t.Fatalf("Parse(%q) returned a token with ok=false", in)
		}
		if ok && (token == "" || token != strings.TrimSpace(token)) {
			t.Fatalf("Parse(%q) = %q, empty or untrimmed", in, token)
		}
		if ok && !strings.Contains(strings.ToLower(in), "bearer") {
			t.Fatalf("Parse(%q) accepted a value without the scheme", in)
		}
	})
}
