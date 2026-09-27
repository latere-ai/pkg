// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import "time"

// Model is one entry of a model list. The zero value of every field but
// Name is what the four APIs write for a model that has no such datum:
// DisplayName defaults to Name, OwnedBy to "owner", Created to the
// epoch, Methods to ["generateContent","countTokens"].
//
// ContextWindow, MaxOutputTokens, InputModalities, and Pricing are the
// figures a client sizes its context and accounts its spend by. Each is
// written after the members the wire's clients read, in the members of
// the wire's own model object where it has them and in members beside
// them otherwise, which the OpenAI and Anthropic clients ignore; a zero
// figure is left out, never written as zero, so an entry without figures
// is the shape it always was:
//
//	wire       window            output limit       input modalities   prices
//	openai     context_window    max_output_tokens  input_modalities   pricing, snake case
//	anthropic  max_input_tokens  max_tokens         input_modalities   pricing, snake case
//	google     inputTokenLimit   outputTokenLimit   none               none
//	lux        contextWindow     maxOutputTokens    modalities.input   pricing, camel case
//
// The Anthropic and Google members are those APIs' own; the lux wire
// names them as the Lux Model kind does.
type Model struct {
	Name        string
	DisplayName string    // the Anthropic and Google shapes
	OwnedBy     string    // the OpenAI shape
	Created     time.Time // created on the OpenAI shape, created_at on Anthropic's
	Methods     []string  // supportedGenerationMethods on the Google shape

	// ContextWindow is the input window in tokens, as Anthropic's
	// max_input_tokens is, and MaxOutputTokens the most tokens one
	// response may hold.
	ContextWindow   int
	MaxOutputTokens int
	// InputModalities are the kinds of content the model takes in, such
	// as "text" and "image". The Google shape has no member for them.
	InputModalities []string
	// Pricing is the model's prices. The Google shape has no member for
	// them.
	Pricing *ModelPricing
}

// ModelPricing is a model's prices, each a decimal string per 1,000,000
// tokens, which the pricing member states with a per of 1000000 so no
// reader takes it for a price per token, as OpenRouter's list quotes
// one. A price quoted per another count is the caller's to convert. An
// empty price is left out.
type ModelPricing struct {
	Currency    string // an ISO 4217 code
	Input       string
	Output      string
	CachedInput string // a cache read
	CacheWrite  string
}

// pricePer is the token count every listed price is quoted per.
const pricePer = 1_000_000

// The defaults of an entry.
const (
	defaultOwner = "owner"
	epochRFC3339 = "1970-01-01T00:00:00Z"
)

var defaultMethods = []string{"generateContent", "countTokens"}

type openaiModel struct {
	ID              string        `json:"id"`
	Object          string        `json:"object"`
	Created         int64         `json:"created"`
	OwnedBy         string        `json:"owned_by"`
	ContextWindow   int           `json:"context_window,omitempty"`
	MaxOutputTokens int           `json:"max_output_tokens,omitempty"`
	InputModalities []string      `json:"input_modalities,omitempty"`
	Pricing         *snakePricing `json:"pricing,omitempty"`
}

type openaiModelList struct {
	Object string        `json:"object"`
	Data   []openaiModel `json:"data"`
}

// luxModel is the OpenAI entry with the figures named as the Lux Model
// kind names them.
type luxModel struct {
	ID              string         `json:"id"`
	Object          string         `json:"object"`
	Created         int64          `json:"created"`
	OwnedBy         string         `json:"owned_by"`
	ContextWindow   int            `json:"contextWindow,omitempty"`
	MaxOutputTokens int            `json:"maxOutputTokens,omitempty"`
	Modalities      *luxModalities `json:"modalities,omitempty"`
	Pricing         *camelPricing  `json:"pricing,omitempty"`
}

type luxModalities struct {
	Input []string `json:"input"`
}

type luxModelList struct {
	Object string     `json:"object"`
	Data   []luxModel `json:"data"`
}

type anthropicModel struct {
	Type            string        `json:"type"`
	ID              string        `json:"id"`
	DisplayName     string        `json:"display_name"`
	CreatedAt       string        `json:"created_at"`
	MaxInputTokens  int           `json:"max_input_tokens,omitempty"`
	MaxTokens       int           `json:"max_tokens,omitempty"`
	InputModalities []string      `json:"input_modalities,omitempty"`
	Pricing         *snakePricing `json:"pricing,omitempty"`
}

// snakePricing is the pricing member of the OpenAI and Anthropic shapes.
type snakePricing struct {
	Currency    string `json:"currency,omitempty"`
	Per         int    `json:"per"`
	Input       string `json:"input,omitempty"`
	Output      string `json:"output,omitempty"`
	CachedInput string `json:"cached_input,omitempty"`
	CacheWrite  string `json:"cache_write,omitempty"`
}

// camelPricing is the pricing member of the lux shape, the Lux Model
// kind's spec.pricing.
type camelPricing struct {
	Currency    string `json:"currency,omitempty"`
	Per         int    `json:"per"`
	Input       string `json:"input,omitempty"`
	Output      string `json:"output,omitempty"`
	CachedInput string `json:"cachedInput,omitempty"`
	CacheWrite  string `json:"cacheWrite,omitempty"`
}

func (p *ModelPricing) snake() *snakePricing {
	if p == nil {
		return nil
	}
	return &snakePricing{Currency: p.Currency, Per: pricePer, Input: p.Input, Output: p.Output, CachedInput: p.CachedInput, CacheWrite: p.CacheWrite}
}

func (p *ModelPricing) camel() *camelPricing {
	if p == nil {
		return nil
	}
	return &camelPricing{Currency: p.Currency, Per: pricePer, Input: p.Input, Output: p.Output, CachedInput: p.CachedInput, CacheWrite: p.CacheWrite}
}

type anthropicModelList struct {
	Data    []anthropicModel `json:"data"`
	HasMore bool             `json:"has_more"`
	FirstID *string          `json:"first_id"`
	LastID  *string          `json:"last_id"`
}

type googleModel struct {
	Name                       string   `json:"name"`
	DisplayName                string   `json:"displayName"`
	SupportedGenerationMethods []string `json:"supportedGenerationMethods"`
	InputTokenLimit            int      `json:"inputTokenLimit,omitempty"`
	OutputTokenLimit           int      `json:"outputTokenLimit,omitempty"`
}

type googleModelList struct {
	Models []googleModel `json:"models"`
}

func openaiEntry(m Model) openaiModel {
	e := openaiModel{ID: m.Name, Object: "model", OwnedBy: m.OwnedBy,
		ContextWindow: m.ContextWindow, MaxOutputTokens: m.MaxOutputTokens,
		InputModalities: m.InputModalities, Pricing: m.Pricing.snake()}
	if e.OwnedBy == "" {
		e.OwnedBy = defaultOwner
	}
	if !m.Created.IsZero() {
		e.Created = m.Created.Unix()
	}
	return e
}

func luxEntry(m Model) luxModel {
	o := openaiEntry(m)
	e := luxModel{ID: o.ID, Object: o.Object, Created: o.Created, OwnedBy: o.OwnedBy,
		ContextWindow: m.ContextWindow, MaxOutputTokens: m.MaxOutputTokens, Pricing: m.Pricing.camel()}
	if len(m.InputModalities) > 0 {
		e.Modalities = &luxModalities{Input: m.InputModalities}
	}
	return e
}

func anthropicEntry(m Model) anthropicModel {
	e := anthropicModel{Type: "model", ID: m.Name, DisplayName: m.DisplayName, CreatedAt: epochRFC3339,
		MaxInputTokens: m.ContextWindow, MaxTokens: m.MaxOutputTokens,
		InputModalities: m.InputModalities, Pricing: m.Pricing.snake()}
	if e.DisplayName == "" {
		e.DisplayName = m.Name
	}
	if !m.Created.IsZero() {
		e.CreatedAt = m.Created.UTC().Format(time.RFC3339)
	}
	return e
}

func googleEntry(m Model) googleModel {
	e := googleModel{Name: "models/" + m.Name, DisplayName: m.DisplayName, SupportedGenerationMethods: m.Methods,
		InputTokenLimit: m.ContextWindow, OutputTokenLimit: m.MaxOutputTokens}
	if e.DisplayName == "" {
		e.DisplayName = m.Name
	}
	if e.SupportedGenerationMethods == nil {
		e.SupportedGenerationMethods = defaultMethods
	}
	return e
}

// ModelList renders models in the wire's list shape, one trailing
// newline, in the order given; sorting is the caller's. OpenAI's and
// the lux wire's is {"object":"list","data":[...]}, Anthropic's
// {"data":[...],"has_more":false,"first_id","last_id"} with the two ids
// null when the list is empty, Google's {"models":[...]} with every
// name under "models/". Each entry carries its figures as Model
// documents. A wire that is none of the four renders nil.
func ModelList(w Wire, models []Model) []byte {
	switch w {
	case WireOpenAI:
		list := openaiModelList{Object: "list", Data: make([]openaiModel, 0, len(models))}
		for _, m := range models {
			list.Data = append(list.Data, openaiEntry(m))
		}
		return append(marshal(list), '\n')
	case WireLux:
		list := luxModelList{Object: "list", Data: make([]luxModel, 0, len(models))}
		for _, m := range models {
			list.Data = append(list.Data, luxEntry(m))
		}
		return append(marshal(list), '\n')
	case WireAnthropic:
		list := anthropicModelList{Data: make([]anthropicModel, 0, len(models))}
		for _, m := range models {
			list.Data = append(list.Data, anthropicEntry(m))
		}
		if len(models) > 0 {
			list.FirstID, list.LastID = &list.Data[0].ID, &list.Data[len(list.Data)-1].ID
		}
		return append(marshal(list), '\n')
	case WireGoogle:
		list := googleModelList{Models: make([]googleModel, 0, len(models))}
		for _, m := range models {
			list.Models = append(list.Models, googleEntry(m))
		}
		return append(marshal(list), '\n')
	}
	return nil
}

// ModelEntry renders one model in the wire's entry shape, one trailing
// newline, and nil for a wire that is none of the four.
func ModelEntry(w Wire, m Model) []byte {
	switch w {
	case WireOpenAI:
		return append(marshal(openaiEntry(m)), '\n')
	case WireLux:
		return append(marshal(luxEntry(m)), '\n')
	case WireAnthropic:
		return append(marshal(anthropicEntry(m)), '\n')
	case WireGoogle:
		return append(marshal(googleEntry(m)), '\n')
	}
	return nil
}
