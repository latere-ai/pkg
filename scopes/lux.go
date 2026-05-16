package scopes

// Lux scopes gate the lux LLM gateway (luxd, lux.latere.ai). read is
// the console read surface (usage analytics, request feed, model
// catalog, settings reads); invoke is the day-to-day grant: proxy an
// upstream provider plus manage your own provider keys, virtual keys,
// access profile, and hooks; admin is org-wide custody: platform /
// org / env-source provider keys, model-catalog writes, org settings,
// and other principals' access profiles.
//
// Wire names keep lux's `llm.<verb>` form (dot, not the `verb:resource`
// colon other services use) because luxd already gates ~30 call sites
// on these exact strings via id.HasScope; renaming them is a separate
// breaking change, not a registry edit.
var (
	LuxRead   = Scope{Name: "llm.read", Description: "Read LLM gateway usage, request feed, model catalog, and settings.", Category: "Lux"}
	LuxInvoke = Scope{Name: "llm.invoke", Description: "Proxy upstream providers and manage your own provider keys, virtual keys, access profile, and hooks.", Category: "Lux"}
	LuxAdmin  = Scope{Name: "llm.admin", Description: "Org-wide LLM gateway custody: platform/org/env provider keys, model-catalog writes, org settings, other principals' profiles.", Category: "Lux"}
)

func lux() []Scope { return []Scope{LuxRead, LuxInvoke, LuxAdmin} }
