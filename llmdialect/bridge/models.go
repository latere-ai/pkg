// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package bridge

import "time"

// Model is one entry of a model list. The zero value of every field but
// Name is what the four APIs write for a model that has no such datum:
// DisplayName defaults to Name, OwnedBy to "owner", Created to the
// epoch, Methods to ["generateContent","countTokens"].
type Model struct {
	Name        string
	DisplayName string    // the Anthropic and Google shapes
	OwnedBy     string    // the OpenAI shape
	Created     time.Time // created on the OpenAI shape, created_at on Anthropic's
	Methods     []string  // supportedGenerationMethods on the Google shape
}

// The defaults of an entry.
const (
	defaultOwner = "owner"
	epochRFC3339 = "1970-01-01T00:00:00Z"
)

var defaultMethods = []string{"generateContent", "countTokens"}

type openaiModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}

type openaiModelList struct {
	Object string        `json:"object"`
	Data   []openaiModel `json:"data"`
}

type anthropicModel struct {
	Type        string `json:"type"`
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
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
}

type googleModelList struct {
	Models []googleModel `json:"models"`
}

func openaiEntry(m Model) openaiModel {
	e := openaiModel{ID: m.Name, Object: "model", OwnedBy: m.OwnedBy}
	if e.OwnedBy == "" {
		e.OwnedBy = defaultOwner
	}
	if !m.Created.IsZero() {
		e.Created = m.Created.Unix()
	}
	return e
}

func anthropicEntry(m Model) anthropicModel {
	e := anthropicModel{Type: "model", ID: m.Name, DisplayName: m.DisplayName, CreatedAt: epochRFC3339}
	if e.DisplayName == "" {
		e.DisplayName = m.Name
	}
	if !m.Created.IsZero() {
		e.CreatedAt = m.Created.UTC().Format(time.RFC3339)
	}
	return e
}

func googleEntry(m Model) googleModel {
	e := googleModel{Name: "models/" + m.Name, DisplayName: m.DisplayName, SupportedGenerationMethods: m.Methods}
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
// name under "models/". A wire that is none of the four renders nil.
func ModelList(w Wire, models []Model) []byte {
	switch w {
	case WireOpenAI, WireLux:
		list := openaiModelList{Object: "list", Data: make([]openaiModel, 0, len(models))}
		for _, m := range models {
			list.Data = append(list.Data, openaiEntry(m))
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
	case WireOpenAI, WireLux:
		return append(marshal(openaiEntry(m)), '\n')
	case WireAnthropic:
		return append(marshal(anthropicEntry(m)), '\n')
	case WireGoogle:
		return append(marshal(googleEntry(m)), '\n')
	}
	return nil
}
