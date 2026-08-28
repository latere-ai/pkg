package ir_test

import (
	"errors"
	"fmt"
	"testing"

	"latere.ai/x/pkg/llmdialect/ir"
)

// A nil error is not a refusal. Returning ScopeDialect for nil would
// read as "advisory refusal" at any call site that forgot its err != nil
// guard, which is the direction that silently forwards nothing.
func TestRefusalScopeOfNil(t *testing.T) {
	t.Parallel()
	if got := ir.RefusalScopeOf(nil); got != ir.ScopeNone {
		t.Fatalf("RefusalScopeOf(nil) = %q, want ScopeNone", got)
	}
}

// Untagged is advisory. A codec opts in to the stricter reading and
// never out of it, so a new error site added later cannot make a gateway
// start rejecting requests its targets would have accepted.
func TestUntaggedErrorIsDialectScoped(t *testing.T) {
	t.Parallel()
	if got := ir.RefusalScopeOf(errors.New("openaichat: unknown role \"system\"")); got != ir.ScopeDialect {
		t.Fatalf("untagged error = %q, want ScopeDialect", got)
	}
}

// The tag must survive the fmt.Errorf("%w") layers the codecs wrap
// errors in on the way out. Without this the taxonomy silently degrades
// to ScopeDialect the first time a tagged site sits under a wrap, which
// is the failure mode that would forward a refused request.
func TestRefusalSurvivesWrapping(t *testing.T) {
	t.Parallel()
	base := ir.RefuseSurface(errors.New("store:true is not supported"))
	wrapped := fmt.Errorf("openairesp: %w", fmt.Errorf("input[0]: %w", base))
	if got := ir.RefusalScopeOf(wrapped); got != ir.ScopeSurface {
		t.Fatalf("wrapped refusal = %q, want ScopeSurface", got)
	}
}

// Tagging is transparent: the message a gateway puts in a 400 body must
// not change, and errors.Is must still reach the cause.
func TestRefusalIsTransparent(t *testing.T) {
	t.Parallel()
	cause := errors.New("store:true is not supported")
	tagged := ir.RefuseSurface(cause)
	if tagged.Error() != cause.Error() {
		t.Fatalf("Error() = %q, want the unchanged message %q", tagged.Error(), cause.Error())
	}
	if !errors.Is(tagged, cause) {
		t.Fatal("errors.Is cannot reach the cause through the tag")
	}
}

// RefuseSurface(nil) is nil, so a codec can tag a conditional error
// without a nil check at every site.
func TestRefuseSurfaceNil(t *testing.T) {
	t.Parallel()
	if err := ir.RefuseSurface(nil); err != nil {
		t.Fatalf("RefuseSurface(nil) = %v, want nil", err)
	}
}
