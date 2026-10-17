// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pricelist_test

import (
	"fmt"
	"strings"

	"latere.ai/x/pkg/pricelist"
)

func ExampleDecode() {
	list := `{"data":[
	 {"id":"anthropic/claude-haiku-5.5","pricing":{"prompt":"0.0000001","completion":"0.0000005",
	  "overrides":[{"min_prompt_tokens":100000,"prompt":"0.0000005","completion":"0.0000025"}]}},
	 {"id":"openrouter/auto","pricing":{"prompt":"-1","completion":"-1"}}
	]}`
	models, err := pricelist.Decode(strings.NewReader(list))
	if err != nil {
		fmt.Println("decode:", err)
		return
	}
	for _, m := range models {
		in, ok := m.Prices.Prompt.PerMillion()
		if !ok {
			fmt.Printf("%s: no fixed price\n", m.ID)
			continue
		}
		out, _ := m.Prices.Completion.PerMillion()
		fmt.Printf("%s: %d in, %d out, micro-USD per million tokens\n", m.ID, in, out)
		for _, tier := range m.LongContext {
			in, _ := tier.Prices.Prompt.PerMillion()
			fmt.Printf("  from %d prompt tokens: %d in\n", tier.MinPromptTokens, in)
		}
	}
	// Output:
	// anthropic/claude-haiku-5.5: 100000 in, 500000 out, micro-USD per million tokens
	//   from 100000 prompt tokens: 500000 in
	// openrouter/auto: no fixed price
}
