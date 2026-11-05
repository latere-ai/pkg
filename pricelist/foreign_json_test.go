// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package pricelist

import (
	"strings"
	"testing"
)

func TestDecodeAcceptsDuplicateNamesAndMixedCase(t *testing.T) {
	models, err := Decode(strings.NewReader(`{"DATA":[{"id":"a","ID":"b","name":"x` + "\xff" + `y"}]}`))
	if err != nil || len(models) != 1 || models[0].ID != "b" {
		t.Errorf("got %+v %v", models, err)
	}
}
