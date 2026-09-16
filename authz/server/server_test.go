// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	otelapi "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"latere.ai/x/pkg/authz"
	"latere.ai/x/pkg/authz/conformance"
	"latere.ai/x/pkg/authz/server"
)

const (
	bearer  = "current-bearer"
	next    = "next-bearer"
	alice   = "https://issuer.example|alice"
	repoID  = "0f5c1d2e-3a4b-4c5d-8e6f-7a8b9c0d1e2f"
	repoKnd = "Repository"
)

// vocabulary is Origo spec 028's four-row table: one kind, three
// decisions and a list.
func vocabulary(t testing.TB) authz.Vocabulary {
	t.Helper()
	v, err := authz.NewVocabulary("origo",
		authz.Action{Name: "repo.read", Kind: repoKnd},
		authz.Action{Name: "repo.write", Kind: repoKnd},
		authz.Action{Name: "repo.admin", Kind: repoKnd},
		authz.Action{Name: "repo.list", Kind: repoKnd})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// deciderFunc and listerFunc let a case be one closure.
type deciderFunc func(ctx context.Context, req authz.Request) (authz.Decision, error)

func (f deciderFunc) Decide(ctx context.Context, req authz.Request) (authz.Decision, error) {
	return f(ctx, req)
}

type listerFunc func(ctx context.Context, req authz.Request) (any, error)

func (f listerFunc) List(ctx context.Context, req authz.Request) (any, error) { return f(ctx, req) }

// allows is the decider a test uses when the decision is not the point.
// It allows everything, the probe included, which is how a case proves
// the scaffold denies the probe itself.
var allows = deciderFunc(func(context.Context, authz.Request) (authz.Decision, error) {
	return authz.Decision{Allow: true}, nil
})

func envelope(subject, action, kind, id string) string {
	res := `{"kind":"` + kind + `"`
	if id != "" {
		res += `,"id":"` + id + `"`
	}
	res += `,"owner":"acme"}`
	if kind == "" {
		res = `{"id":"` + id + `"}`
	}
	return `{"subject":"` + subject + `","issuer":"https://issuer.example","sub":"alice","claims":{},` +
		`"action":"` + action + `","resource":` + res + `,"request":{"id":"r1","ip":"203.0.113.4","user_agent":"t"}}`
}

// post sends one body and returns the status and the decoded object.
func post(t testing.TB, h http.Handler, token, body string) (int, map[string]any) {
	t.Helper()
	status, raw := postRaw(t, h, http.MethodPost, token, body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("the answer is not a JSON object: %v (%s)", err, raw)
		}
	}
	return status, out
}

func postRaw(t testing.TB, h http.Handler, method, token, body string) (int, []byte) {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, raw
}

func TestNewRefusesAWiringMistake(t *testing.T) {
	for _, tc := range []struct {
		name string
		o    server.Options
		want string
	}{
		{"no decider", server.Options{Vocabulary: vocabulary(t)}, "needs a Decider"},
		{"no vocabulary", server.Options{Decider: allows}, "needs a Vocabulary"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				v := recover()
				if v == nil {
					t.Fatal("New built a handler that can answer nothing")
				}
				if s, _ := v.(string); !strings.Contains(s, tc.want) {
					t.Fatalf("panic = %v; it names %q", v, tc.want)
				}
			}()
			server.New(tc.o)
		})
	}
}

func TestTheBearerIsTheCurrentOneOrItsSuccessor(t *testing.T) {
	body := envelope(alice, "repo.read", repoKnd, repoID)
	for _, tc := range []struct {
		name               string
		bearer, bearerNext string
		header             string
		want               int
	}{
		{"the current bearer", bearer, next, "Bearer " + bearer, http.StatusOK},
		{"the successor, mid-rotation", bearer, next, "Bearer " + next, http.StatusOK},
		{"the successor alone", "", next, "Bearer " + next, http.StatusOK},
		{"a wrong bearer", bearer, next, "Bearer wrong", http.StatusUnauthorized},
		{"the retired bearer", next, "", "Bearer " + bearer, http.StatusUnauthorized},
		{"no header", bearer, next, "", http.StatusUnauthorized},
		{"the token with no scheme", bearer, next, bearer, http.StatusUnauthorized},
		{"another scheme", bearer, next, "Basic " + bearer, http.StatusUnauthorized},
		{"the scheme with no token", bearer, next, "Bearer ", http.StatusUnauthorized},
		// net/textproto trims a header's outer whitespace, so only an
		// inner space reaches the handler; it is not trimmed away either.
		{"a padded token", bearer, next, "Bearer  " + bearer, http.StatusUnauthorized},
		{"an endpoint configured with neither", "", "", "Bearer " + bearer, http.StatusUnauthorized},
		{"an endpoint configured with neither, no header", "", "", "", http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := server.New(server.Options{Bearer: tc.bearer, BearerNext: tc.bearerNext,
				Vocabulary: vocabulary(t), Decider: allows})
			status, out := post(t, h, tc.header, body)
			if status != tc.want {
				t.Fatalf("status = %d; want %d (%v)", status, tc.want, out)
			}
			if status == http.StatusUnauthorized {
				if out["error"] != "unauthorized" || out["message"] != "A bearer token is required." {
					t.Fatalf("the 401 body = %v", out)
				}
				if _, decided := out["allow"]; decided {
					t.Fatal("a refused call carries a verdict")
				}
			}
		})
	}
}

func TestAnotherMethodIsRefused(t *testing.T) {
	h := server.New(server.Options{Bearer: bearer, Vocabulary: vocabulary(t), Decider: allows})
	srv := httptest.NewServer(h)
	defer srv.Close()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET answered %d", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != http.MethodPost {
		t.Fatalf("Allow = %q", got)
	}
}

func TestAMalformedRequestIsA400(t *testing.T) {
	big := strings.Repeat("x", 1024)
	for _, tc := range []struct {
		name, body string
		maxBody    int64
		detail     string
	}{
		{name: "a body that is not JSON", body: "{not json", detail: "invalid character"},
		{name: "a body that is a list", body: `[{"action":"repo.read"}]`, detail: "cannot unmarshal"},
		{name: "an unknown action", body: envelope(alice, "repo.raed", repoKnd, repoID),
			detail: "action must be one of origo's vocabulary; got repo.raed"},
		{name: "an action with no name", body: envelope(alice, "", repoKnd, repoID),
			detail: "action must be one of origo's vocabulary; got "},
		{name: "a kind that is not the action's", body: envelope(alice, "repo.read", "Sandbox", repoID),
			detail: "resource.kind must be Repository for repo.read; got Sandbox"},
		{name: "a body over the bound", maxBody: 256,
			body:   `{"action":"repo.read","resource":{"kind":"Repository","id":"` + big + `"}}`,
			detail: "too large"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := server.New(server.Options{Bearer: bearer, Vocabulary: vocabulary(t),
				MaxBody: tc.maxBody, Decider: deciderFunc(func(context.Context, authz.Request) (authz.Decision, error) {
					t.Error("the decider was asked about a malformed request")
					return authz.Decision{}, nil
				})})
			status, out := post(t, h, "Bearer "+bearer, tc.body)
			if status != http.StatusBadRequest {
				t.Fatalf("status = %d; want 400 (%v)", status, out)
			}
			if out["error"] != "invalid_request" || out["message"] != "The request body could not be read." {
				t.Fatalf("the 400 body = %v", out)
			}
			detail, _ := out["detail"].(string)
			if !strings.Contains(detail, tc.detail) {
				t.Fatalf("detail = %q; it names %q", detail, tc.detail)
			}
		})
	}
}

// TestTheDefaultBodyBound: an envelope the size of a real one passes and
// one past the default does not, without MaxBody being named.
func TestTheDefaultBodyBound(t *testing.T) {
	h := server.New(server.Options{Bearer: bearer, Vocabulary: vocabulary(t), Decider: allows})
	if status, out := post(t, h, "Bearer "+bearer, envelope(alice, "repo.read", repoKnd, repoID)); status != http.StatusOK {
		t.Fatalf("a real envelope answered %d (%v)", status, out)
	}
	oversized := `{"action":"repo.read","claims":{"pad":"` + strings.Repeat("x", server.DefaultMaxBody) + `"}}`
	if status, _ := post(t, h, "Bearer "+bearer, oversized); status != http.StatusBadRequest {
		t.Fatalf("a body past %d bytes answered %d", server.DefaultMaxBody, status)
	}
}

// TestTheProbeIsDeniedBeforeTheDecider: the reserved id is denied for
// every subject and every action, a list action included, whatever the
// decider would have said. A core's check command reads an allow on it as
// an endpoint that does not read the request, so the scaffold owns the
// rule rather than trusting a decider with it.
func TestTheProbeIsDeniedBeforeTheDecider(t *testing.T) {
	h := server.New(server.Options{Bearer: bearer, Vocabulary: vocabulary(t),
		Decider: allows,
		Lister: listerFunc(func(context.Context, authz.Request) (any, error) {
			t.Error("the probe reached the lister")
			return nil, nil
		})})
	for _, subject := range []string{"", alice, "https://issuer.example|bob"} {
		for _, action := range []string{"repo.read", "repo.admin", "repo.list"} {
			for _, id := range []string{authz.ProbeID, strings.ToUpper(authz.ProbeID)} {
				what := fmt.Sprintf("the probe as %q for %s", subject, action)
				status, out := post(t, h, "Bearer "+bearer, envelope(subject, action, repoKnd, id))
				if status != http.StatusOK {
					t.Fatalf("%s answered %d", what, status)
				}
				if out["allow"] != false || out["reason"] != authz.ReasonProbe {
					t.Fatalf("%s answered %v; the probe is denied with a reason", what, out)
				}
			}
		}
	}
}

// TestADecisionIsWrittenWhole: the verdict, the reason, the ttl capped at
// the contract's maximum, the core's own limits object and the filter.
func TestADecisionIsWrittenWhole(t *testing.T) {
	for _, tc := range []struct {
		name string
		d    authz.Decision
		want string
	}{
		{"an allow with nothing else", authz.Decision{Allow: true}, `{"allow":true}`},
		{"a deny with its reason", authz.Decision{Reason: "not_owner"}, `{"allow":false,"reason":"not_owner"}`},
		{"an allow with a ttl", authz.Decision{Allow: true, TTL: 30 * time.Second}, `{"allow":true,"ttl":30}`},
		{"a ttl over the cap", authz.Decision{Allow: true, TTL: 2 * authz.MaxTTL},
			`{"allow":true,"ttl":` + fmt.Sprint(int(authz.MaxTTL/time.Second)) + `}`},
		{"a ttl under a second", authz.Decision{Allow: true, TTL: time.Millisecond}, `{"allow":true}`},
		{"the core's limits", authz.Decision{Allow: true, Limits: json.RawMessage(`{"quota_bytes":10}`)},
			`{"allow":true,"limits":{"quota_bytes":10}}`},
		{"a filter", authz.Decision{Allow: true, Filter: &authz.Filter{Owners: []string{"acme"}}},
			`{"allow":true,"filter":{"owners":["acme"]}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := server.New(server.Options{Bearer: bearer, Vocabulary: vocabulary(t),
				Decider: deciderFunc(func(_ context.Context, req authz.Request) (authz.Decision, error) {
					if req.Subject != alice || req.Resource.String("owner") != "acme" {
						t.Errorf("the decider was handed %+v; the envelope arrives whole", req)
					}
					return tc.d, nil
				})})
			status, raw := postRaw(t, h, http.MethodPost, "Bearer "+bearer, envelope(alice, "repo.read", repoKnd, repoID))
			if status != http.StatusOK {
				t.Fatalf("status = %d", status)
			}
			if got := strings.TrimSpace(string(raw)); got != tc.want {
				t.Fatalf("body = %s; want %s", got, tc.want)
			}
			d, err := authz.ParseDecision(raw)
			if err != nil || d.Allow != tc.d.Allow {
				t.Fatalf("the client reads the body as %+v, %v", d, err)
			}
		})
	}
}

// TestADeciderThatCannotAnswerIsA503: ErrUnavailable, wrapped or not, is
// the one 503, and it is never an allow. Any other error is the
// endpoint's own fault and a 500.
func TestADeciderThatCannotAnswerIsA503(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		status  int
		code    string
		message string
	}{
		{"the sentinel", server.ErrUnavailable, http.StatusServiceUnavailable, "unavailable",
			"Permissions cannot be checked right now. Try again in a few minutes."},
		{"the sentinel wrapped", fmt.Errorf("snapshot: %w", server.ErrUnavailable),
			http.StatusServiceUnavailable, "unavailable",
			"Permissions cannot be checked right now. Try again in a few minutes."},
		{"the sentinel with a reason", server.Unavailable("stale_snapshot"),
			http.StatusServiceUnavailable, "unavailable",
			"Permissions cannot be checked right now. Try again in a few minutes."},
		{"any other error", errors.New("the store did not answer"), http.StatusInternalServerError,
			"internal_error", "Something went wrong. Try again in a few minutes."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := server.New(server.Options{Bearer: bearer, Vocabulary: vocabulary(t),
				Decider: deciderFunc(func(context.Context, authz.Request) (authz.Decision, error) {
					return authz.Decision{Allow: true}, tc.err
				})})
			status, out := post(t, h, "Bearer "+bearer, envelope(alice, "repo.write", repoKnd, repoID))
			if status != tc.status {
				t.Fatalf("status = %d; want %d (%v)", status, tc.status, out)
			}
			if out["error"] != tc.code || out["message"] != tc.message {
				t.Fatalf("body = %v", out)
			}
			if _, decided := out["allow"]; decided {
				t.Fatalf("a call that produced no decision carries a verdict: %v", out)
			}
			if _, leaked := out["detail"]; leaked {
				t.Fatalf("the decider's error reached the core: %v", out)
			}
		})
	}
}

func TestUnavailableCarriesAReasonAndStaysTheSentinel(t *testing.T) {
	err := server.Unavailable("no_snapshot")
	if !errors.Is(err, server.ErrUnavailable) {
		t.Fatal("Unavailable is not ErrUnavailable")
	}
	if !strings.Contains(err.Error(), "no_snapshot") {
		t.Fatalf("Error() = %q", err)
	}
}

// TestAListIsTheCoresOwnPage: a list action routes to the Lister, whose
// value is written as it is; with no Lister it is a 400, because the
// endpoint cannot decide it and a 200 that is no answer is worse.
func TestAListIsTheCoresOwnPage(t *testing.T) {
	v := vocabulary(t)
	page := map[string]any{"repos": []any{map[string]any{"id": repoID, "owner": "acme", "slug": "app"}}, "next_cursor": "c2"}
	for _, tc := range []struct {
		name   string
		lister server.Lister
		status int
		check  func(t *testing.T, out map[string]any)
	}{
		{name: "a page", status: http.StatusOK,
			lister: listerFunc(func(_ context.Context, req authz.Request) (any, error) {
				if req.Action != "repo.list" {
					t.Errorf("the lister was handed %q", req.Action)
				}
				return page, nil
			}),
			check: func(t *testing.T, out map[string]any) {
				if out["next_cursor"] != "c2" || len(out["repos"].([]any)) != 1 {
					t.Fatalf("the page was rewritten: %v", out)
				}
			}},
		{name: "a refusal in the core's own shape", status: http.StatusOK,
			lister: listerFunc(func(context.Context, authz.Request) (any, error) {
				return map[string]any{"allow": false, "reason": "not_in_org"}, nil
			}),
			check: func(t *testing.T, out map[string]any) {
				if out["allow"] != false || out["reason"] != "not_in_org" {
					t.Fatalf("out = %v", out)
				}
			}},
		{name: "an installation with no directory", status: http.StatusOK,
			lister: listerFunc(func(context.Context, authz.Request) (any, error) {
				return map[string]any{"directory": false}, nil
			}),
			check: func(t *testing.T, out map[string]any) {
				if out["directory"] != false {
					t.Fatalf("out = %v", out)
				}
			}},
		{name: "a lister that cannot answer", status: http.StatusServiceUnavailable,
			lister: listerFunc(func(context.Context, authz.Request) (any, error) {
				return nil, server.Unavailable("no_snapshot")
			}),
			check: func(t *testing.T, out map[string]any) {
				if out["error"] != "unavailable" {
					t.Fatalf("out = %v", out)
				}
			}},
		{name: "no lister at all", status: http.StatusBadRequest, lister: nil,
			check: func(t *testing.T, out map[string]any) {
				detail, _ := out["detail"].(string)
				if !strings.Contains(detail, "no directory is served here") {
					t.Fatalf("detail = %q", detail)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := server.New(server.Options{Bearer: bearer, Vocabulary: v, Lister: tc.lister,
				Decider: deciderFunc(func(context.Context, authz.Request) (authz.Decision, error) {
					t.Error("a list action reached the decider")
					return authz.Decision{}, nil
				})})
			status, out := post(t, h, "Bearer "+bearer, envelope(alice, "repo.list", repoKnd, ""))
			if status != tc.status {
				t.Fatalf("status = %d; want %d (%v)", status, tc.status, out)
			}
			tc.check(t, out)
		})
	}
}

// TestEveryAnswerPastValidationIsCounted: the counter carries the result
// and the reason, and the 401s and 400s that never reached a decider are
// not counted — they are not decisions.
func TestEveryAnswerPastValidationIsCounted(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	meter := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader)).Meter("authz/server test")
	v := vocabulary(t)
	answers := map[string]authz.Decision{
		"repo.read":  {Allow: true},
		"repo.write": {Reason: "not_owner"},
	}
	h := server.New(server.Options{Bearer: bearer, Vocabulary: v, Meter: meter,
		Decider: deciderFunc(func(_ context.Context, req authz.Request) (authz.Decision, error) {
			if req.Action == "repo.admin" {
				return authz.Decision{}, server.Unavailable("stale_snapshot")
			}
			return answers[req.Action], nil
		}),
		Lister: listerFunc(func(context.Context, authz.Request) (any, error) {
			return map[string]any{"repos": []any{}}, nil
		})})
	for _, action := range []string{"repo.read", "repo.write", "repo.admin", "repo.list"} {
		id := repoID
		if action == "repo.list" {
			id = ""
		}
		post(t, h, "Bearer "+bearer, envelope(alice, action, repoKnd, id))
	}
	post(t, h, "Bearer "+bearer, envelope("", "repo.read", repoKnd, authz.ProbeID))
	// Neither of these is a decision, so neither is counted.
	post(t, h, "Bearer wrong", envelope(alice, "repo.read", repoKnd, repoID))
	post(t, h, "Bearer "+bearer, envelope(alice, "repo.raed", repoKnd, repoID))

	want := map[[2]string]int64{
		{"allow", ""}:                     1,
		{"deny", "not_owner"}:             1,
		{"deny", "probe"}:                 1,
		{"unavailable", "stale_snapshot"}: 1,
		{"list", "repo.list"}:             1,
	}
	got := counted(t, reader, "latere.authz.decisions")
	if len(got) != len(want) {
		t.Fatalf("the counter carries %v; want %v", got, want)
	}
	for k, n := range want {
		if got[k] != n {
			t.Fatalf("{result=%q reason=%q} = %d; want %d (all: %v)", k[0], k[1], got[k], n, got)
		}
	}
}

// counted reads one counter's points as {result, reason} -> value.
func counted(t testing.TB, reader sdkmetric.Reader, name string) map[[2]string]int64 {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[[2]string]int64{}
	for _, scope := range rm.ScopeMetrics {
		for _, m := range scope.Metrics {
			if m.Name != name {
				continue
			}
			sum, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				t.Fatalf("%s is %T; a decision counter is a sum", name, m.Data)
			}
			for _, p := range sum.DataPoints {
				result, _ := p.Attributes.Value(attribute.Key("result"))
				reason, _ := p.Attributes.Value(attribute.Key("reason"))
				out[[2]string{result.AsString(), reason.AsString()}] += p.Value
			}
		}
	}
	return out
}

// TestAMeterWithNoCounterIsNotAnOutage: an instrument the SDK refuses is
// logged and the endpoint keeps answering. An authorizer that stops
// deciding because a metric could not be built is an outage of the core
// in front of it.
func TestAMeterWithNoCounterIsNotAnOutage(t *testing.T) {
	h := server.New(server.Options{Bearer: bearer, Vocabulary: vocabulary(t), Decider: allows,
		Meter: failingMeter{Meter: otelapi.Meter("failing")}})
	if status, out := post(t, h, "Bearer "+bearer, envelope(alice, "repo.read", repoKnd, repoID)); status != http.StatusOK || out["allow"] != true {
		t.Fatalf("status = %d, out = %v", status, out)
	}
}

type failingMeter struct{ metric.Meter }

func (failingMeter) Int64Counter(string, ...metric.Int64CounterOption) (metric.Int64Counter, error) {
	return nil, errors.New("this meter builds no counter")
}

// TestTheScaffoldConforms: a conformance run against server.New over a
// decider of four lines passes every rule of the contract, driven by the
// vocabulary. It is the proof that a self-hoster who writes Decide and
// nothing else has a conforming authorizer.
func TestTheScaffoldConforms(t *testing.T) {
	v := vocabulary(t)
	h := server.New(server.Options{Bearer: "secret", Vocabulary: v,
		Decider: deciderFunc(func(_ context.Context, req authz.Request) (authz.Decision, error) {
			if req.Subject == "" {
				return authz.Decision{Reason: authz.ReasonAnonymous}, nil
			}
			return authz.Decision{Allow: true, TTL: 30 * time.Second}, nil
		}),
		Lister: listerFunc(func(context.Context, authz.Request) (any, error) {
			return map[string]any{"repos": []any{}}, nil
		})})
	srv := httptest.NewServer(h)
	defer srv.Close()
	conformance.Run(t, srv.URL, "secret", conformance.WithVocabulary(v))
}

// FuzzTheEnvelopeIsValidatedBeforeTheDecider: whatever the body, a 200
// that allows is a request the scaffold let through, which means a known
// action, a kind that is the action's, and an id that is not the probe's.
// The decider under it allows everything, so every refusal in the corpus
// is the scaffold's own.
func FuzzTheEnvelopeIsValidatedBeforeTheDecider(f *testing.F) {
	v := vocabulary(f)
	h := server.New(server.Options{Bearer: bearer, Vocabulary: v, Decider: allows,
		Lister: listerFunc(func(context.Context, authz.Request) (any, error) {
			return map[string]any{"repos": []any{}}, nil
		})})
	srv := httptest.NewServer(h)
	f.Cleanup(srv.Close)
	for _, s := range []string{
		envelope(alice, "repo.read", repoKnd, repoID),
		envelope(alice, "repo.read", repoKnd, authz.ProbeID),
		envelope(alice, "repo.raed", repoKnd, repoID),
		envelope(alice, "repo.read", "Sandbox", repoID),
		`{"action":"repo.read","resource":null}`,
		"{not json",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, body string) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, strings.NewReader(body))
		if err != nil {
			t.Skip()
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := srv.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			return
		}
		var out map[string]any
		if json.Unmarshal(raw, &out) != nil || out["allow"] != true {
			return
		}
		var sent authz.Request
		if err := json.Unmarshal([]byte(body), &sent); err != nil {
			t.Fatalf("a body that does not decode was allowed: %s", body)
		}
		kind, known := v.Kind(sent.Action)
		switch {
		case !known:
			t.Fatalf("%q is outside the vocabulary and was allowed", sent.Action)
		case sent.Resource.Kind != "" && sent.Resource.Kind != kind:
			t.Fatalf("resource.kind %q is not %q's and was allowed", sent.Resource.Kind, sent.Action)
		case strings.EqualFold(sent.Resource.ID, authz.ProbeID):
			t.Fatal("the probe id was allowed")
		}
	})
}
