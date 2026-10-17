// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pricelist

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// listPayload is a trimmed copy of OpenRouter's model list: a model with
// every figure and both cache-write lifetimes, one priced by prompt length,
// one priced by the time of day, a free variant, a model priced per request,
// a model with a malformed price, rows with figures in unexpected forms, and
// a row with no id.
const listPayload = `{"data":[
 {"id":"anthropic/claude-opus-5.5","name":"Anthropic: Claude Opus 5.5","created":1791331200,
  "architecture":{"input_modalities":["text","image","file"],"output_modalities":["text"]},"context_length":1000000,
  "top_provider":{"context_length":1000000,"max_completion_tokens":128000},
  "supported_parameters":["reasoning","tools"],
  "pricing":{"prompt":"0.000004","completion":"0.00002","web_search":"0.01","input_cache_read":"0.0000002","input_cache_write":"0.000005","input_cache_write_1h":"0.000008"}},
 {"id":"anthropic/claude-haiku-5.5","pricing":{"prompt":"0.0000001","completion":"0.0000005","input_cache_read":"0.00000001","input_cache_write":"0.000000125","input_cache_write_1h":"0.0000002",
  "overrides":[{"min_prompt_tokens":100000,"prompt":"0.0000005","completion":"0.0000025","input_cache_read":"0.00000005","input_cache_write":"0.000000625","input_cache_write_1h":"0.000001"}]}},
 {"id":"acme/off-peak","pricing":{"prompt":"0.00000015","completion":"0.0000006",
  "overrides":[{"utc_days":["saturday","sunday"],"prompt":"0.00000015","completion":"0.0000006"},{"utc_start":100,"utc_end":400,"prompt":"0.0000003","completion":"0.0000012"},{"min_prompt_tokens":272000,"utc_days":["monday"],"prompt":"0.0000009","completion":"0.000003"},{"min_prompt_tokens":0,"prompt":"0.1","completion":"0.1"},{"min_prompt_tokens":272000,"utc_days":null,"prompt":"0.0000004"}]}},
 {"id":"OpenAI/GPT-6:free","supported_parameters":[],"pricing":{"prompt":"0","completion":"0"}},
 {"id":"openrouter/auto","pricing":{"prompt":"-1","completion":"-1"}},
 {"id":"acme/garbled","pricing":{"prompt":"0.000001","completion":"one dollar","input_cache_read":null}},
 {"id":"acme/odd","created":"soon","context_length":"200000","top_provider":{"max_completion_tokens":1.5},"pricing":{"prompt":"0.000001","completion":"0.000002"}},
 {"id":"acme/negative","created":-5,"context_length":-1,"top_provider":{"max_completion_tokens":null},"pricing":{}},
 {"id":"","pricing":{"prompt":"0.1","completion":"0.1"}}
]}`

// micro is a price's PerMillion, or -1 for a price that is not a fixed one.
func micro(p Price) int64 {
	if v, ok := p.PerMillion(); ok {
		return v
	}
	return -1
}

// prices is a Prices' five PerMillion figures, -1 for each that is not a
// fixed price.
func prices(p Prices) [5]int64 {
	return [5]int64{micro(p.Prompt), micro(p.Completion), micro(p.InputCacheRead), micro(p.InputCacheWrite), micro(p.InputCacheWrite1h)}
}

func byID(t *testing.T, models []Model) map[string]Model {
	t.Helper()
	out := make(map[string]Model, len(models))
	for _, m := range models {
		if _, dup := out[m.ID]; dup {
			t.Fatalf("model %q read twice", m.ID)
		}
		out[m.ID] = m
	}
	return out
}

// TestDecodeReadsEveryRowAsWritten: each row with an id comes back in the
// list's order, under its id as written, with its figures and its five
// prices, and a row with no id is left out.
func TestDecodeReadsEveryRowAsWritten(t *testing.T) {
	models, err := Decode(strings.NewReader(listPayload))
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range models {
		ids = append(ids, m.ID)
	}
	want := []string{"anthropic/claude-opus-5.5", "anthropic/claude-haiku-5.5", "acme/off-peak", "OpenAI/GPT-6:free", "openrouter/auto", "acme/garbled", "acme/odd", "acme/negative"}
	if !slices.Equal(ids, want) {
		t.Fatalf("ids %v, want %v", ids, want)
	}
	got := byID(t, models)

	opus := got["anthropic/claude-opus-5.5"]
	if opus.Name != "Anthropic: Claude Opus 5.5" || !opus.Created.Equal(time.Unix(1791331200, 0)) || opus.Created.Location() != time.UTC {
		t.Errorf("opus name %q created %v", opus.Name, opus.Created)
	}
	if opus.ContextLength != 1_000_000 || opus.MaxCompletionTokens != 128_000 {
		t.Errorf("opus window %d output limit %d", opus.ContextLength, opus.MaxCompletionTokens)
	}
	if !slices.Equal(opus.SupportedParameters, []string{"reasoning", "tools"}) {
		t.Errorf("opus parameters %v", opus.SupportedParameters)
	}
	if !slices.Equal(opus.InputModalities, []string{"text", "image", "file"}) || !slices.Equal(opus.OutputModalities, []string{"text"}) {
		t.Errorf("opus modalities %v in, %v out", opus.InputModalities, opus.OutputModalities)
	}
	if m := got["acme/odd"]; m.InputModalities != nil || m.OutputModalities != nil {
		t.Errorf("a row with no architecture read modalities %v in, %v out", m.InputModalities, m.OutputModalities)
	}
	if p := prices(opus.Prices); p != [5]int64{4_000_000, 20_000_000, 200_000, 5_000_000, 8_000_000} {
		t.Errorf("opus prices %v", p)
	}
	if opus.LongContext != nil {
		t.Errorf("opus, priced the same at every length, has tiers %+v", opus.LongContext)
	}

	if p := prices(got["anthropic/claude-haiku-5.5"].Prices); p != [5]int64{100_000, 500_000, 10_000, 125_000, 200_000} {
		t.Errorf("haiku base prices %v", p)
	}

	free := got["OpenAI/GPT-6:free"]
	if !free.Prices.Prompt.Zero() || !free.Prices.Completion.Zero() || free.Prices.InputCacheRead.Stated() {
		t.Errorf("free variant prices %+v, want two exact zeros and no cache price", free.Prices)
	}
	if free.SupportedParameters == nil || len(free.SupportedParameters) != 0 {
		t.Errorf("a stated empty parameter list read as %#v", free.SupportedParameters)
	}
	if opus.SupportedParameters == nil || got["acme/odd"].SupportedParameters != nil {
		t.Error("a row stating no parameter list read as stating one, or the reverse")
	}

	auto := got["openrouter/auto"].Prices.Prompt
	if _, ok := auto.PerMillion(); ok || !auto.Stated() || auto.Zero() {
		t.Errorf("a price set per request read as %+v", auto)
	}
}

// TestDecodeKeepsAMalformedPriceToItsModel: a price that is no decimal costs
// its model that price alone; the model's other prices and the rest of the
// list read as written.
func TestDecodeKeepsAMalformedPriceToItsModel(t *testing.T) {
	models, err := Decode(strings.NewReader(listPayload))
	if err != nil {
		t.Fatal(err)
	}
	garbled := byID(t, models)["acme/garbled"].Prices
	if p := prices(garbled); p != [5]int64{1_000_000, -1, -1, -1, -1} {
		t.Errorf("garbled prices %v", p)
	}
	if !garbled.Completion.Stated() || garbled.Completion.Zero() {
		t.Errorf("a malformed price read as %+v, want stated and not zero", garbled.Completion)
	}
	if garbled.InputCacheRead.Stated() {
		t.Error("a null price read as stated")
	}
}

// TestDecodeReadsAFigureInAnUnexpectedFormAsNotStated: a count or a time
// that is not a positive integer is zero, and the row is still read.
func TestDecodeReadsAFigureInAnUnexpectedFormAsNotStated(t *testing.T) {
	models, err := Decode(strings.NewReader(listPayload))
	if err != nil {
		t.Fatal(err)
	}
	got := byID(t, models)
	for _, id := range []string{"acme/odd", "acme/negative"} {
		m := got[id]
		if !m.Created.IsZero() || m.ContextLength != 0 || m.MaxCompletionTokens != 0 {
			t.Errorf("%s: created %v window %d output limit %d, want none", id, m.Created, m.ContextLength, m.MaxCompletionTokens)
		}
	}
	if p := prices(got["acme/odd"].Prices); p[0] != 1_000_000 || p[1] != 2_000_000 {
		t.Errorf("acme/odd prices %v", p)
	}
}

// TestDecodeReadsTheLongContextTiers: an override conditioned on the
// prompt's length alone is a tier, with the prices it states and no others,
// and one conditioned on the time of day, or on no positive length, is not.
func TestDecodeReadsTheLongContextTiers(t *testing.T) {
	models, err := Decode(strings.NewReader(listPayload))
	if err != nil {
		t.Fatal(err)
	}
	got := byID(t, models)

	haiku := got["anthropic/claude-haiku-5.5"].LongContext
	if len(haiku) != 1 || haiku[0].MinPromptTokens != 100_000 {
		t.Fatalf("haiku tiers %+v", haiku)
	}
	if p := prices(haiku[0].Prices); p != [5]int64{500_000, 2_500_000, 50_000, 625_000, 1_000_000} {
		t.Errorf("haiku tier prices %v", p)
	}

	offPeak := got["acme/off-peak"].LongContext
	if len(offPeak) != 1 || offPeak[0].MinPromptTokens != 272_000 {
		t.Fatalf("off-peak tiers %+v, want the one conditioned on length alone", offPeak)
	}
	tier := offPeak[0].Prices
	if micro(tier.Prompt) != 400_000 || tier.Completion.Stated() || tier.InputCacheWrite1h.Stated() {
		t.Errorf("a tier stating only its prompt price read as %+v", tier)
	}
}

// TestDecodeRefusesWhatIsNoList: a body that is not JSON, a price of the
// wrong JSON type, a list cut by the size bound, and a list with no model
// are errors rather than a list with no prices in it.
func TestDecodeRefusesWhatIsNoList(t *testing.T) {
	cut := `{"data":[` + strings.Repeat(" ", maxListBytes) + `{"id":"acme/a","pricing":{"prompt":"0.000001","completion":"0.000002"}}]}`
	for name, body := range map[string]string{
		"not json":          `<html>`,
		"empty":             ``,
		"numeric price":     `{"data":[{"id":"acme/a","pricing":{"prompt":0.000001,"completion":"0.000002"}}]}`,
		"override list":     `{"data":[{"id":"acme/a","pricing":{"prompt":"0.000001","overrides":{"min_prompt_tokens":1}}}]}`,
		"no data":           `{}`,
		"empty data":        `{"data":[]}`,
		"only rows sans id": `{"data":[{"pricing":{"prompt":"0.1"}},null]}`,
		"past the bound":    cut,
	} {
		if models, err := Decode(strings.NewReader(body)); err == nil {
			t.Errorf("%s: decoded %d models, want an error", name, len(models))
		}
	}
}

// serve answers every request with status and body, and records the
// User-Agent of the last one.
func serve(t *testing.T, status int, body string) (*httptest.Server, *string) {
	t.Helper()
	var agent string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		agent = r.UserAgent()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv, &agent
}

// TestFetchReadsTheList: a 200 answer is decoded, with the User-Agent the
// option sets, or the client's own without it, and a nil client is the
// instrumented default.
func TestFetchReadsTheList(t *testing.T) {
	srv, agent := serve(t, http.StatusOK, listPayload)
	models, err := Fetch(t.Context(), srv.Client(), srv.URL, WithUserAgent("pricelist-test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(models) != 8 || *agent != "pricelist-test" {
		t.Fatalf("%d models, User-Agent %q", len(models), *agent)
	}
	if _, err := Fetch(t.Context(), nil, srv.URL, WithUserAgent("")); err != nil {
		t.Fatalf("a nil client: %v", err)
	}
	if *agent == "" || *agent == "pricelist-test" {
		t.Fatalf("an empty agent sent %q, want the client's default", *agent)
	}
}

// failing is a transport that fails every request.
type failing struct{}

var errTransport = errors.New("connection refused")

func (failing) RoundTrip(*http.Request) (*http.Response, error) { return nil, errTransport }

// TestFetchRefusesAFailedRead: a status other than 200, a body that is no
// list, a request that cannot be sent and an address that cannot be read
// are errors.
func TestFetchRefusesAFailedRead(t *testing.T) {
	down, _ := serve(t, http.StatusServiceUnavailable, listPayload)
	if _, err := Fetch(t.Context(), down.Client(), down.URL); err == nil || !strings.Contains(err.Error(), "status 503") {
		t.Errorf("a 503: %v", err)
	}
	html, _ := serve(t, http.StatusOK, `<html>`)
	if _, err := Fetch(t.Context(), html.Client(), html.URL); err == nil {
		t.Error("a page that is no list was read as one")
	}
	if _, err := Fetch(t.Context(), &http.Client{Transport: failing{}}, DefaultURL); !errors.Is(err, errTransport) {
		t.Errorf("a failed request: %v, want the transport's error", err)
	}
	if _, err := Fetch(t.Context(), nil, "http://bad host/"); err == nil {
		t.Error("an address with a space was read")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := Fetch(ctx, html.Client(), html.URL); !errors.Is(err, context.Canceled) {
		t.Errorf("a canceled read: %v", err)
	}
}

// FuzzDecode holds Decode to its contract on any body: it never panics, and
// a list it reads holds at least one model, each with an id.
func FuzzDecode(f *testing.F) {
	f.Add([]byte(listPayload))
	f.Add([]byte(`{"data":[{"id":"a/b","pricing":{"prompt":"1e-6","overrides":[{"min_prompt_tokens":5}]}}]}`))
	f.Add([]byte(`{"data":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		models, err := Decode(strings.NewReader(string(body)))
		if err != nil {
			return
		}
		if len(models) == 0 {
			t.Fatal("a list with no model was read without an error")
		}
		for _, m := range models {
			if m.ID == "" {
				t.Fatal("a row with no id was read as a model")
			}
			for _, tier := range m.LongContext {
				if tier.MinPromptTokens <= 0 {
					t.Fatalf("a tier from no positive length: %+v", tier)
				}
			}
		}
	})
}
