package scopes

// BillingReport gates the meter-submission endpoint auth exposes at
// /internal/billing/* and the cella billing reporter calls.
var BillingReport = Scope{Name: "billing:report", Description: "Submit usage events to the meter pipeline.", Category: "Billing"}

func billing() []Scope { return []Scope{BillingReport} }
