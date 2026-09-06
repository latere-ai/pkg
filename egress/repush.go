// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package egress

// CredSecret is a credential's real value + destinations, resolved from the
// credential store at re-push time. Kept out of any durable store: the gateway
// holds it only in memory, and it is re-derived on each re-push.
type CredSecret struct {
	Secret []byte
	Hosts  []string
}

// RebuildMap reconstructs a principal's substitution map for a gateway re-push
// by joining the LIVE placeholders, read back from the running workload's
// environment and keyed by credential name, with the secrets + hosts
// re-projected from the credential store, keyed by the same name. This is the
// crux of the HA design: the control plane never retained the random
// per-create placeholder, and re-projecting the store mints a *different*
// one, so the map can only be reproduced by pairing the workload's actual
// placeholder with the store's secret. A credential present in only one side
// is skipped (its placeholder or secret is gone). The secret bytes never
// touch disk: they flow store → memory → gateway, as at create.
func RebuildMap(placeholders map[string]string, secrets map[string]CredSecret) []IngestEntry {
	out := make([]IngestEntry, 0, len(placeholders))
	for name, ph := range placeholders {
		if ph == "" || !IsPlaceholder(ph) {
			continue
		}
		s, ok := secrets[name]
		if !ok {
			continue // no secret for this placeholder: drop it (nothing to substitute)
		}
		out = append(out, IngestEntryFor(ph, s.Secret, s.Hosts))
	}
	return out
}
