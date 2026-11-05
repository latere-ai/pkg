// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

// Package wirejson holds the JSON options the dialect packages share.
package wirejson

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
)

// In reads what a model provider, or a client written for one, sends: model
// output, tool-call arguments, provider responses and stream events. It is not
// JSON we produce, so duplicate names, invalid UTF-8 and any letter case are
// accepted.
var In = json.JoinOptions(
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
	json.MatchCaseInsensitiveNames(true),
)

// Out writes a request or response for a service we do not own. Keys are
// sorted so equal payloads are equal bytes, which provider prompt caches key
// on. A nil slice or map is null, because some providers reject [] where they
// accept null. Raw values embedded from a provider keep duplicate names and
// invalid UTF-8 instead of failing the write.
var Out = json.JoinOptions(
	json.Deterministic(true),
	json.FormatNilSliceAsNull(true),
	json.FormatNilMapAsNull(true),
	jsontext.AllowDuplicateNames(true),
	jsontext.AllowInvalidUTF8(true),
)
