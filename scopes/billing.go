package scopes

// Billing scopes gate access to the auth service's billing endpoints
// (/internal/billing/*) and the cella billing reporter.
var (
	BillingRead   = Scope{Name: "billing:read", Description: "Read billing accounts and usage records.", Category: "Billing"}
	BillingReport = Scope{Name: "billing:report", Description: "Submit usage events to the meter pipeline.", Category: "Billing"}
)

func billing() []Scope { return []Scope{BillingRead, BillingReport} }
