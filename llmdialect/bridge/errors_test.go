// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import (
	"errors"
	"strings"
	"testing"

	"latere.ai/x/pkg/llmdialect"
	"latere.ai/x/pkg/llmdialect/ir"
)

// codes lists the seven, in the order they are declared.
var codes = []Code{DecodeRequest, EncodeRequest, DecodeResponse, EncodeResponse, StreamFailed, WriteFailed, Unsupported}

// TestCodesHaveOneSentenceEach is the registers rule over the seven:
// every code has one fixed user sentence, no two share one, no sentence
// names a package or a function, and a string that is not a code has
// none.
func TestCodesHaveOneSentenceEach(t *testing.T) {
	seen := map[string]Code{}
	for _, c := range codes {
		msg := c.Message()
		if msg == "" || !strings.HasSuffix(msg, ".") || strings.Count(msg, ". ") > 0 {
			t.Errorf("%s: message %q is not one sentence", c, msg)
		}
		if strings.Contains(msg, "codec") || strings.Contains(msg, "llmdialect") || strings.Contains(msg, "(") {
			t.Errorf("%s: message %q is written for a developer", c, msg)
		}
		if other, dup := seen[msg]; dup {
			t.Errorf("%s and %s share the sentence %q", c, other, msg)
		}
		seen[msg] = c
	}
	if Code("bogus").Message() != "" {
		t.Error("a string that is not a code has a sentence")
	}
}

// TestErrorRendering: Error is "<code>: <detail>" or the code alone,
// Message the code's sentence, Unwrap the codec's error.
func TestErrorRendering(t *testing.T) {
	cause := errors.New("bad json")
	e := wrap(EncodeRequest, cause)
	if e.Error() != "encode_request: bad json" || e.Message() != EncodeRequest.Message() || !errors.Is(e, cause) || e.Scope != llmdialect.ScopeNone {
		t.Errorf("%+v", e)
	}
	if (&Error{Code: Unsupported}).Error() != "unsupported" {
		t.Error("an Error with no detail renders more than the code")
	}
	// A decode refusal carries the codec's scope, surface when tagged.
	d := wrap(DecodeRequest, ir.RefuseSurface(cause))
	if d.Scope != llmdialect.ScopeSurface || Scope(d) != llmdialect.ScopeSurface {
		t.Errorf("surface refusal: %s %s", d.Scope, Scope(d))
	}
	if a := wrap(DecodeRequest, cause); a.Scope != llmdialect.ScopeDialect || Scope(a) != llmdialect.ScopeDialect {
		t.Errorf("dialect refusal: %s", a.Scope)
	}
	if Scope(nil) != llmdialect.ScopeNone {
		t.Error("Scope(nil)")
	}
}
