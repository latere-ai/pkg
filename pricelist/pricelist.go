// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package pricelist reads a model list in OpenRouter's format, such as
// OpenRouter's public one at [DefaultURL], into typed per-model prices and
// the figures that describe each model. It is unofficial and is not
// published by OpenRouter.
//
// A price is read exactly: the list writes USD per token as a decimal
// string, and [Price] holds it as micro-USD per million tokens, rounded
// half-even, with an exact zero, a price that is no fixed price and an
// absent price told apart. What a reader does with a model the list prices
// partly, or with a variant such as ":free" or ":batch", is the reader's
// rule; this package reads every row as written.
//
// # Usage
//
//	models, err := pricelist.Fetch(ctx, client, pricelist.DefaultURL)
//	if err != nil {
//		return err
//	}
//	for _, m := range models {
//		if in, ok := m.Prices.Prompt.PerMillion(); ok {
//			fmt.Println(m.ID, in)
//		}
//	}
package pricelist

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"latere.ai/x/pkg/otel"
)

// DefaultURL is OpenRouter's public model list.
const DefaultURL = "https://openrouter.ai/api/v1/models"

// maxListBytes bounds what Decode reads: far above the size of OpenRouter's
// list, and low enough that a hostile list cannot hold a reader's memory.
const maxListBytes = 16 << 20

// Model is one row of the list.
type Model struct {
	// ID is the model's id as the list writes it, such as
	// "anthropic/claude-opus-5.5" or "openai/gpt-6:free". Case and white
	// space are kept.
	ID string
	// Name is the display name as the list writes it, such as
	// "Anthropic: Claude Opus 5.5".
	Name string
	// Created is when the list first listed the model, in UTC, and zero
	// when the row states no positive Unix time.
	Created time.Time
	// ContextLength is the model's context window in tokens, and
	// MaxCompletionTokens its top provider's output limit. Zero is a
	// figure the row does not state as a positive integer.
	ContextLength       int
	MaxCompletionTokens int
	// SupportedParameters are the request parameters the model takes, such
	// as "reasoning" or "tools": nil when the row states no list, and empty,
	// not nil, when it states an empty one.
	SupportedParameters []string
	// InputModalities are the kinds of content the model takes, such as
	// ["text", "image"], and OutputModalities what it outputs, such as
	// ["text"], as the list writes them; nil when the row states none.
	InputModalities  []string
	OutputModalities []string
	// Prices are the model's base prices.
	Prices Prices
	// LongContext are the tiers that replace the base prices for a long
	// prompt, in the order the list writes them; nil for a model priced the
	// same at every prompt length.
	LongContext []Tier
}

// Prices are the token prices of a model or of one of its tiers. A price
// the row does not state is the zero Price.
type Prices struct {
	// Prompt is the price of an input token and Completion that of an
	// output token.
	Prompt     Price `json:"prompt"`
	Completion Price `json:"completion"`
	// InputCacheRead is the price of an input token read from the
	// provider's prompt cache.
	InputCacheRead Price `json:"input_cache_read"`
	// InputCacheWrite is the price of an input token written to the prompt
	// cache at the provider's default lifetime, and InputCacheWrite1h at a
	// one-hour lifetime.
	InputCacheWrite   Price `json:"input_cache_write"`
	InputCacheWrite1h Price `json:"input_cache_write_1h"`
}

// Tier is a long-context price tier: the prices that apply instead of the
// base ones to a request whose prompt holds at least MinPromptTokens
// tokens. A tier may state only some prices; the rest are the zero Price.
type Tier struct {
	MinPromptTokens int
	Prices          Prices
}

// Option changes one setting of a Fetch.
type Option func(*fetchConfig)

// fetchConfig is what the options of one Fetch set.
type fetchConfig struct {
	userAgent string
}

// WithUserAgent sets the User-Agent header of the request, so the list's
// host can tell the reader apart. An empty value leaves the HTTP client's
// default.
func WithUserAgent(agent string) Option {
	return func(c *fetchConfig) { c.userAgent = agent }
}

// Fetch reads the list at url through client, otel.HTTPClient() when nil,
// and decodes it with Decode. A status other than 200 is an error. The
// caller bounds the call with ctx or with the client's Timeout.
func Fetch(ctx context.Context, client *http.Client, url string, opts ...Option) ([]Model, error) {
	if client == nil {
		client = otel.HTTPClient()
	}
	var cfg fetchConfig
	for _, opt := range opts {
		opt(&cfg)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("pricelist: GET %s: %w", url, err)
	}
	if cfg.userAgent != "" {
		req.Header.Set("User-Agent", cfg.userAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("pricelist: GET %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("pricelist: GET %s: status %d", url, resp.StatusCode)
	}
	return Decode(resp.Body)
}

// Decode reads a list from r, at most 16 MiB of it, and returns its models
// in the order the list writes them. A row without an id is no model and is
// left out, and a list with no model is an error, so an outage that answers
// an empty list is never read as a list with no prices in it.
//
// The list's shape is checked as encoding/json checks it: a price that is
// neither a JSON string nor null, or a name or a list of the wrong JSON
// type, fails the decode. A count or a time in an unexpected form, such as
// a context length written as a string, is a figure the row does not
// state, and costs the model that figure and never the list.
//
// Of the list's price overrides, those conditioned on the prompt's length
// alone are read as LongContext tiers. An override conditioned on the time
// of day is no long-context tier and is left out.
func Decode(r io.Reader) ([]Model, error) {
	var body struct {
		Data []row `json:"data"`
	}
	if err := json.NewDecoder(io.LimitReader(r, maxListBytes)).Decode(&body); err != nil {
		return nil, fmt.Errorf("pricelist: decode the list: %w", err)
	}
	out := make([]Model, 0, len(body.Data))
	for _, m := range body.Data {
		if m.ID == "" {
			continue
		}
		model := Model{
			ID:                  m.ID,
			Name:                m.Name,
			ContextLength:       int(m.ContextLength),
			MaxCompletionTokens: int(m.TopProvider.MaxCompletionTokens),
			SupportedParameters: m.SupportedParameters,
			InputModalities:     m.Architecture.InputModalities,
			OutputModalities:    m.Architecture.OutputModalities,
			Prices:              m.Pricing.Prices,
		}
		if m.Created > 0 {
			model.Created = time.Unix(int64(m.Created), 0).UTC()
		}
		for _, o := range m.Pricing.Overrides {
			if o.MinPromptTokens > 0 && !present(o.UTCDays) && !present(o.UTCStart) && !present(o.UTCEnd) {
				model.LongContext = append(model.LongContext, Tier{MinPromptTokens: int(o.MinPromptTokens), Prices: o.Prices})
			}
		}
		out = append(out, model)
	}
	if len(out) == 0 {
		return nil, errors.New("pricelist: the list holds no model")
	}
	return out, nil
}

// row is one model as the list writes it.
type row struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Created      count  `json:"created"`
	Architecture struct {
		InputModalities  []string `json:"input_modalities"`
		OutputModalities []string `json:"output_modalities"`
	} `json:"architecture"`
	ContextLength       count    `json:"context_length"`
	SupportedParameters []string `json:"supported_parameters"`
	TopProvider         struct {
		MaxCompletionTokens count `json:"max_completion_tokens"`
	} `json:"top_provider"`
	Pricing struct {
		Prices
		Overrides []override `json:"overrides"`
	} `json:"pricing"`
}

// override is one entry of a row's price overrides: the prices that apply
// under its conditions, a prompt of at least min_prompt_tokens or a window
// of UTC days and hours. The window is read for its presence alone, so a
// change to its form never fails the decode.
type override struct {
	Prices
	MinPromptTokens count           `json:"min_prompt_tokens"`
	UTCDays         json.RawMessage `json:"utc_days"`
	UTCStart        json.RawMessage `json:"utc_start"`
	UTCEnd          json.RawMessage `json:"utc_end"`
}

// present reports whether an override states a condition: a member that is
// there and not null.
func present(raw json.RawMessage) bool {
	return len(raw) > 0 && string(raw) != "null"
}

// count is a count or a Unix time in the list: a positive JSON integer, and
// zero for null, an absent member and any other value.
type count int

// UnmarshalJSON implements json.Unmarshaler. A value that is not a positive
// integer reads as zero, which callers take as a figure not stated.
func (c *count) UnmarshalJSON(b []byte) error {
	*c = 0
	if n, err := strconv.ParseInt(string(b), 10, 0); err == nil && n > 0 {
		*c = count(n)
	}
	return nil
}
