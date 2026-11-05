// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pricelist

import (
	"encoding/json/v2"
	"testing"
)

func TestPriceDecodesInvalidUTF8(t *testing.T) {
	var p Price
	if err := json.Unmarshal([]byte("\"0.5\xff\""), &p, foreignJSON); err != nil {
		t.Fatalf("invalid UTF-8 in a price failed the decode: %v", err)
	}
}
