// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package provenance

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/propagation"

	"latere.ai/x/pkg/authkit"
	pkgotel "latere.ai/x/pkg/otel"
)

const (
	testIssuer = "https://auth.latere.ai"
	testSub    = "4a1f2c6e-1c9b-4d0a-9d4e-0c6b1a2f3e44"
	testEntry  = "platform.latere.ai"
	testWant   = testIssuer + "|" + testSub
)

// TestMain installs the composite propagator otel.Bootstrap installs in a
// live process (pkg/otel/telemetry.go). The OTel global default is a no-op,
// so without this the round-trip tests would propagate nothing and pass for
// the wrong reason. It is process-global, so no test here runs in parallel.
func TestMain(m *testing.M) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	os.Exit(m.Run())
}

func person() authkit.Identity {
	return authkit.Identity{Sub: testSub, PrincipalType: authkit.PrincipalUser}
}

// TestMemberKeys pins the three strings the standard names. They are the
// contract with every other repository in the family; renaming one silently
// is the failure this guards.
func TestMemberKeys(t *testing.T) {
	if MemberSubject != "initiator.sub" {
		t.Errorf("MemberSubject = %q, want initiator.sub", MemberSubject)
	}
	if MemberIssuer != "initiator.iss" {
		t.Errorf("MemberIssuer = %q, want initiator.iss", MemberIssuer)
	}
	if MemberEntry != "entry" {
		t.Errorf("MemberEntry = %q, want entry", MemberEntry)
	}
	// The run-tracing prefix must stay disjoint from this one, and neither a
	// substring of the other (run-tracing.md, "Shape").
	for _, k := range []string{MemberSubject, MemberIssuer, MemberEntry} {
		if strings.HasPrefix(k, "run.") {
			t.Errorf("member %q collides with the run. prefix", k)
		}
	}
	// The vocabulary is initiator., never actor.
	for _, k := range []string{MemberSubject, MemberIssuer} {
		if !strings.HasPrefix(k, "initiator.") {
			t.Errorf("member %q is not under the initiator. prefix", k)
		}
	}
}

func TestStampThenFrom(t *testing.T) {
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	got, ok := From(ctx)
	if !ok {
		t.Fatal("From: ok false after Stamp")
	}
	want := Initiator{Subject: testWant, Issuer: testIssuer, Entry: testEntry}
	if got != want {
		t.Errorf("From = %+v, want %+v", got, want)
	}
	// The values reach baggage under the member names, not only the struct.
	b := baggage.FromContext(ctx)
	if v := b.Member(MemberSubject).Value(); v != testWant {
		t.Errorf("baggage %s = %q, want %q", MemberSubject, v, testWant)
	}
	if v := b.Member(MemberIssuer).Value(); v != testIssuer {
		t.Errorf("baggage %s = %q, want %q", MemberIssuer, v, testIssuer)
	}
	if v := b.Member(MemberEntry).Value(); v != testEntry {
		t.Errorf("baggage %s = %q, want %q", MemberEntry, v, testEntry)
	}
}

func TestFromNoBaggage(t *testing.T) {
	got, ok := From(context.Background())
	if ok {
		t.Errorf("From on a bare ctx: ok true, got %+v", got)
	}
	if got != (Initiator{}) {
		t.Errorf("From on a bare ctx = %+v, want zero", got)
	}
}

// TestFromEntryOnly: a front door that set entry and no subject stamped no
// initiator. Subject is what names the person.
func TestFromEntryOnly(t *testing.T) {
	m, err := baggage.NewMember(MemberEntry, testEntry)
	if err != nil {
		t.Fatal(err)
	}
	b, err := baggage.New(m)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := From(baggage.ContextWithBaggage(context.Background(), b)); ok {
		t.Errorf("From with entry alone: ok true, got %+v", got)
	}
}

// TestStampReplacesSpoof: a member that survived the ingress strip loses to
// the identity this hop verified.
func TestStampReplacesSpoof(t *testing.T) {
	spoof := func(t *testing.T, kvs ...[2]string) context.Context {
		t.Helper()
		var ms []baggage.Member
		for _, kv := range kvs {
			m, err := baggage.NewMember(kv[0], kv[1])
			if err != nil {
				t.Fatal(err)
			}
			ms = append(ms, m)
		}
		b, err := baggage.New(ms...)
		if err != nil {
			t.Fatal(err)
		}
		return baggage.ContextWithBaggage(context.Background(), b)
	}

	ctx := spoof(t,
		[2]string{MemberSubject, "https://evil.example|attacker"},
		[2]string{MemberIssuer, "https://evil.example"},
		[2]string{MemberEntry, "evil.example"},
		[2]string{"run.id", "keep-me"},
	)
	ctx = Stamp(ctx, person(), testIssuer, testEntry)

	got, ok := From(ctx)
	if !ok {
		t.Fatal("From: ok false after Stamp over a spoof")
	}
	want := Initiator{Subject: testWant, Issuer: testIssuer, Entry: testEntry}
	if got != want {
		t.Errorf("From = %+v, want %+v", got, want)
	}
	// The other plane's members are not this package's to touch.
	if v := baggage.FromContext(ctx).Member("run.id").Value(); v != "keep-me" {
		t.Errorf("run.id = %q, want keep-me: Stamp cleared a member it does not own", v)
	}
}

// TestStampDeletesUnsetMembers: an edge with no entry configured must not
// leave a spoofed entry standing as half of an initiator.
func TestStampDeletesUnsetMembers(t *testing.T) {
	m, err := baggage.NewMember(MemberEntry, "evil.example")
	if err != nil {
		t.Fatal(err)
	}
	b, err := baggage.New(m)
	if err != nil {
		t.Fatal(err)
	}
	ctx := Stamp(baggage.ContextWithBaggage(context.Background(), b), person(), testIssuer, "")
	if v := baggage.FromContext(ctx).Member(MemberEntry).Value(); v != "" {
		t.Errorf("entry = %q, want empty: Stamp kept an inbound member it did not set", v)
	}
}

func TestStampNoSub(t *testing.T) {
	var buf bytes.Buffer
	defer restoreDefault(t, &buf)()

	ctx := context.Background()
	got := Stamp(ctx, authkit.Identity{PrincipalType: authkit.PrincipalUser}, testIssuer, testEntry)
	if _, ok := From(got); ok {
		t.Error("Stamp with an empty Sub stamped an initiator")
	}
	// An anonymous or unattended context is ordinary, not a misconfiguration.
	if buf.Len() != 0 {
		t.Errorf("Stamp warned about a missing sub: %q", buf.String())
	}
}

// TestStampNoIssuer: authz.Subject renders an empty issuer as "|<sub>", a
// subject no core can qualify. Half an initiator is not an initiator, so
// Stamp writes nothing and says why.
func TestStampNoIssuer(t *testing.T) {
	var buf bytes.Buffer
	defer restoreDefault(t, &buf)()

	got := Stamp(context.Background(), person(), "", testEntry)
	if i, ok := From(got); ok {
		t.Errorf("Stamp with no issuer stamped %+v", i)
	}
	if b := baggage.FromContext(got); len(b.Members()) != 0 {
		t.Errorf("baggage = %v, want empty", b.Members())
	}
	if !strings.Contains(buf.String(), "provenance: no issuer") {
		t.Errorf("no warn line logged, got %q", buf.String())
	}
}

// TestAssertNoIssuer: a hop that cannot render its own subject cannot detect
// a contradiction, and must not 400 every request over a bug of its own.
func TestAssertNoIssuer(t *testing.T) {
	var buf bytes.Buffer
	defer restoreDefault(t, &buf)()

	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	if err := Assert(ctx, person(), ""); err != nil {
		t.Errorf("Assert with no issuer = %v, want nil", err)
	}
	if !strings.Contains(buf.String(), "provenance: no issuer") {
		t.Errorf("no warn line logged, got %q", buf.String())
	}
}

// TestAssertNoSub: a person identity with no sub renders nothing to compare.
func TestAssertNoSub(t *testing.T) {
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	id := authkit.Identity{PrincipalType: authkit.PrincipalUser}
	if err := Assert(ctx, id, testIssuer); err != nil {
		t.Errorf("Assert with no sub = %v, want nil", err)
	}
}

// TestStampNeverFails: a value baggage cannot encode returns ctx unchanged
// and logs at warn. Provenance never breaks a call (provenance.md, "The
// package").
func TestStampNeverFails(t *testing.T) {
	for _, tc := range []struct {
		name          string
		id            authkit.Identity
		issuer, entry string
	}{
		{"subject", authkit.Identity{Sub: "a\x00b", PrincipalType: authkit.PrincipalUser}, testIssuer, testEntry},
		{"entry", person(), testIssuer, "bad\x7fentry"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			prev := slog.Default()
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
			defer slog.SetDefault(prev)

			ctx := Stamp(context.Background(), tc.id, tc.issuer, tc.entry)
			if _, ok := From(ctx); ok {
				t.Error("Stamp encoded a value it should have refused")
			}
			if !strings.Contains(buf.String(), "provenance: initiator not stamped") {
				t.Errorf("no warn line logged, got %q", buf.String())
			}
		})
	}
}

// TestStampNeverFailsLeavesCtxUntouched: the refusal is all-or-nothing, so a
// half-written initiator never reaches the wire.
func TestStampNeverFailsLeavesCtxUntouched(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	defer slog.SetDefault(prev)

	base := Stamp(context.Background(), person(), testIssuer, testEntry)
	got := Stamp(base, person(), testIssuer, "bad\x7fentry")
	i, ok := From(got)
	if !ok || i.Entry != testEntry {
		t.Errorf("From = %+v ok=%v, want the previous stamp intact", i, ok)
	}
}

func TestAssert(t *testing.T) {
	stamped := Stamp(context.Background(), person(), testIssuer, testEntry)
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		id      authkit.Identity
		issuer  string
		wantErr bool
	}{
		{"match", stamped, person(), testIssuer, false},
		{"mismatched sub", stamped, authkit.Identity{Sub: "someone-else", PrincipalType: authkit.PrincipalUser}, testIssuer, true},
		{"mismatched issuer", stamped, person(), "https://evil.example", true},
		{"no baggage", context.Background(), person(), testIssuer, false},
		{"service identity", stamped, authkit.Identity{Sub: "platformd", PrincipalType: authkit.PrincipalService}, testIssuer, false},
		{"agent identity", stamped, authkit.Identity{Sub: "agent-7", PrincipalType: authkit.PrincipalAgent}, testIssuer, false},
		{"dev identity", stamped, authkit.Identity{Sub: "dev", PrincipalType: authkit.PrincipalDev}, testIssuer, false},
		{"unset principal type", stamped, authkit.Identity{Sub: "whoever"}, testIssuer, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := Assert(tc.ctx, tc.id, tc.issuer)
			if tc.wantErr != (err != nil) {
				t.Fatalf("Assert = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr {
				return
			}
			if !errors.Is(err, ErrInitiatorMismatch) {
				t.Errorf("errors.Is(%v, ErrInitiatorMismatch) = false", err)
			}
			var me *MismatchError
			if !errors.As(err, &me) {
				t.Fatalf("errors.As: %v is no *MismatchError", err)
			}
			if me.Baggage != testWant {
				t.Errorf("Baggage = %q, want %q", me.Baggage, testWant)
			}
			if me.Verified == testWant {
				t.Errorf("Verified = %q, want the other subject", me.Verified)
			}
			if !strings.Contains(me.Error(), me.Baggage) || !strings.Contains(me.Error(), me.Verified) {
				t.Errorf("Error() = %q, want both subjects", me.Error())
			}
		})
	}
}

// TestAssertLeavesServiceInitiatorByteIdentical is acceptance criterion A5.
func TestAssertLeavesServiceInitiatorByteIdentical(t *testing.T) {
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	before := members(baggage.FromContext(ctx))
	svc := authkit.Identity{Sub: "platformd", PrincipalType: authkit.PrincipalService}
	if err := Assert(ctx, svc, testIssuer); err != nil {
		t.Fatalf("Assert on a service identity: %v", err)
	}
	if after := members(baggage.FromContext(ctx)); !maps.Equal(after, before) {
		t.Errorf("baggage changed: %v -> %v", before, after)
	}
}

func TestAttrs(t *testing.T) {
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	attrs := Attrs(ctx)
	if len(attrs) != 3 {
		t.Fatalf("Attrs len = %d, want 3: %v", len(attrs), attrs)
	}
	want := map[string]string{MemberSubject: testWant, MemberIssuer: testIssuer, MemberEntry: testEntry}
	for _, a := range attrs {
		w, ok := want[a.Key]
		if !ok {
			t.Errorf("unexpected attr key %q", a.Key)
			continue
		}
		if a.Value.String() != w {
			t.Errorf("attr %s = %q, want %q", a.Key, a.Value.String(), w)
		}
		delete(want, a.Key)
	}
	if len(want) != 0 {
		t.Errorf("attrs missing %v", want)
	}
	if got := Attrs(context.Background()); len(got) != 0 {
		t.Errorf("Attrs on a bare ctx = %v, want empty", got)
	}
}

// TestSpanAttrsMatchAttrs is acceptance criterion A8's package half: a span
// and its log lines carry the same keys and the same values.
func TestSpanAttrsMatchAttrs(t *testing.T) {
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	logAttrs, spanAttrs := Attrs(ctx), SpanAttrs(ctx)
	if len(logAttrs) != len(spanAttrs) {
		t.Fatalf("len: log %d, span %d", len(logAttrs), len(spanAttrs))
	}
	for i := range logAttrs {
		if string(spanAttrs[i].Key) != logAttrs[i].Key {
			t.Errorf("key %d: span %q, log %q", i, spanAttrs[i].Key, logAttrs[i].Key)
		}
		if spanAttrs[i].Value.AsString() != logAttrs[i].Value.String() {
			t.Errorf("value %d: span %q, log %q", i, spanAttrs[i].Value.AsString(), logAttrs[i].Value.String())
		}
	}
	if got := SpanAttrs(context.Background()); len(got) != 0 {
		t.Errorf("SpanAttrs on a bare ctx = %v, want empty", got)
	}
}

// TestPartialInitiatorAttrs: an initiator read from a partial baggage emits
// only the members that carry a value.
func TestPartialInitiatorAttrs(t *testing.T) {
	i := Initiator{Subject: testWant}
	if got := i.Attrs(); len(got) != 1 || got[0].Key != MemberSubject {
		t.Errorf("Attrs = %v, want only %s", got, MemberSubject)
	}
	if got := i.SpanAttrs(); len(got) != 1 || string(got[0].Key) != MemberSubject {
		t.Errorf("SpanAttrs = %v, want only %s", got, MemberSubject)
	}
}

// TestPropagatesTwoHops is acceptance criterion A2: an edge stamps, and the
// three members arrive unchanged at a service two hops away, over the real
// otel client and handler.
func TestPropagatesTwoHops(t *testing.T) {
	type seen struct {
		Initiator Initiator
		OK        bool
		Header    string
	}

	// Hop C: the far end. It reads and never sets.
	cSaw := make(chan seen, 1)
	hopC := httptest.NewServer(otelHandler(func(w http.ResponseWriter, r *http.Request) {
		i, ok := From(r.Context())
		cSaw <- seen{i, ok, r.Header.Get("Baggage")}
		w.WriteHeader(http.StatusNoContent)
	}, "hop-c"))
	defer hopC.Close()

	// Hop B: reads, then calls C on its own credential with the same ctx.
	bSaw := make(chan seen, 1)
	hopB := httptest.NewServer(otelHandler(func(w http.ResponseWriter, r *http.Request) {
		i, ok := From(r.Context())
		bSaw <- seen{i, ok, r.Header.Get("Baggage")}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, hopC.URL, nil)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp, err := otelClient().Do(req)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer func() { _ = resp.Body.Close() }()
		_, _ = io.Copy(io.Discard, resp.Body)
		w.WriteHeader(http.StatusNoContent)
	}, "hop-b"))
	defer hopB.Close()

	// The edge: verifies the person's token, stamps once.
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, hopB.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := otelClient().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	want := Initiator{Subject: testWant, Issuer: testIssuer, Entry: testEntry}
	b, c := <-bSaw, <-cSaw
	if !b.OK || b.Initiator != want {
		t.Errorf("hop B saw %+v ok=%v, want %+v", b.Initiator, b.OK, want)
	}
	if !c.OK || c.Initiator != want {
		t.Errorf("hop C saw %+v ok=%v, want %+v", c.Initiator, c.OK, want)
	}
	if b.Header == "" || c.Header == "" {
		t.Fatalf("no Baggage header on the wire: B %q, C %q", b.Header, c.Header)
	}
	// Baggage renders its members in map order, so compare the parsed sets.
	bb, err := baggage.Parse(b.Header)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := baggage.Parse(c.Header)
	if err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(members(bb), members(cb)) {
		t.Errorf("members changed across the hop: %v -> %v", members(bb), members(cb))
	}
	// The pipe and the URL survive the encoding the wire demands.
	if !strings.Contains(c.Header, MemberSubject+"=") {
		t.Errorf("header %q carries no %s", c.Header, MemberSubject)
	}
}

// TestAuditAttrs pins the audit shape's own fields. at, service, trace_id
// and span_id come from otel.SetupLogs and are not this package's to add.
func TestAuditAttrs(t *testing.T) {
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	attrs := AuditAttrs(ctx, "repository.grant.set", "repository/2f9c8b10", OutcomeAllowed,
		slog.String("org_slug", "acme"))

	got := map[string]string{}
	for _, a := range attrs {
		got[a.Key] = a.Value.String()
	}
	for k, want := range map[string]string{
		AuditKey:         "true",
		MemberSubject:    testWant,
		MemberIssuer:     testIssuer,
		MemberEntry:      testEntry,
		AuditActionKey:   "repository.grant.set",
		AuditResourceKey: "repository/2f9c8b10",
		AuditOutcomeKey:  "allowed",
		"org_slug":       "acme",
	} {
		if got[k] != want {
			t.Errorf("attr %s = %q, want %q", k, got[k], want)
		}
	}
	if len(attrs) != 8 {
		t.Errorf("len = %d, want 8: %v", len(attrs), attrs)
	}
}

// TestAuditAttrsUnattended: a service acting as itself emits no initiator,
// and that absence is the record (provenance.md, Rule 2).
func TestAuditAttrsUnattended(t *testing.T) {
	attrs := AuditAttrs(context.Background(), "repository.deregistered", "repository/x", OutcomeFailed)
	if len(attrs) != 4 {
		t.Fatalf("len = %d, want 4: %v", len(attrs), attrs)
	}
	for _, a := range attrs {
		if strings.HasPrefix(a.Key, "initiator.") || a.Key == MemberEntry {
			t.Errorf("unattended record carries %s", a.Key)
		}
	}
}

func TestAudit(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	ctx := Stamp(context.Background(), person(), testIssuer, testEntry)
	Audit(ctx, logger, "repository.grant.removed", "repository/7", OutcomeDenied)

	var rec map[string]any
	if err := json.Unmarshal(buf.Bytes(), &rec); err != nil {
		t.Fatal(err)
	}
	if rec["msg"] != "repository.grant.removed" {
		t.Errorf("msg = %v, want the action", rec["msg"])
	}
	if rec[AuditKey] != true {
		t.Errorf("%s = %v, want true", AuditKey, rec[AuditKey])
	}
	if rec[MemberSubject] != testWant {
		t.Errorf("%s = %v, want %q", MemberSubject, rec[MemberSubject], testWant)
	}
	if rec[AuditOutcomeKey] != string(OutcomeDenied) {
		t.Errorf("%s = %v, want denied", AuditOutcomeKey, rec[AuditOutcomeKey])
	}
	if rec["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", rec["level"])
	}
}

// TestAuditNilLogger: a nil logger writes to slog.Default rather than
// panicking in the middle of an audited action.
func TestAuditNilLogger(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	defer slog.SetDefault(prev)

	Audit(context.Background(), nil, "repository.registered", "repository/9", OutcomeAllowed)
	if !strings.Contains(buf.String(), "repository.registered") {
		t.Errorf("nothing reached slog.Default: %q", buf.String())
	}
}

// otelHandler and otelClient are the family's real server and client wiring:
// pkg/otel.Handler extracts the propagated context, pkg/otel.HTTPClient
// injects it. The test uses them rather than a stand-in so what it proves is
// what ships.
func otelHandler(h http.HandlerFunc, op string) http.Handler {
	return pkgotel.Handler(h, op)
}

func otelClient() *http.Client { return pkgotel.HTTPClient() }

// members is the member set of b, order-independent: Baggage.String renders
// in map order, which is not stable between calls.
func members(b baggage.Baggage) map[string]string {
	out := map[string]string{}
	for _, m := range b.Members() {
		out[m.Key()] = m.Value()
	}
	return out
}

// restoreDefault points slog.Default at buf for the duration of a test and
// returns the function that puts the previous logger back.
func restoreDefault(t *testing.T, buf *bytes.Buffer) func() {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	return func() { slog.SetDefault(prev) }
}
