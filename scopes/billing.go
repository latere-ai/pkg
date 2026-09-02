// SPDX-FileCopyrightText: 2026 Latere AI
// SPDX-License-Identifier: Apache-2.0

package scopes

// BillingReport gates the meter-submission endpoint auth exposes at
// /internal/billing/*, which a product's usage reporter calls.
var BillingReport = Scope{Name: "billing:report", Description: "Submit usage events to the meter pipeline.", Category: "Billing"}

func billing() []Scope { return []Scope{BillingReport} }
