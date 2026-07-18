package scopes

// Lux scopes gate the lux LLM gateway (luxd, lux.latere.ai). read is
// the console read surface (usage analytics, request feed, model
// catalog, settings reads); invoke is the day-to-day grant: proxy an
// upstream provider plus manage your own provider keys, virtual keys,
// access profile, and hooks; serve lets an identity expose a local model
// runtime through Lux (the reverse-tunnel serve side, GET /lux/v1/tunnel,
// spec 18), a distinct act from invoking; admin is org-wide custody:
// platform / org / env-source provider keys, model-catalog writes, org
// settings, and other principals' access profiles; keyadmin is a
// server-to-server capability that mints and revokes owner-scoped virtual
// keys (POST/DELETE /lux/v1/admin/keys), kept distinct from admin so an
// org admin cannot mint keys owned by an arbitrary org.
//
// Wire names keep lux's `llm.<verb>` form (dot, not the `verb:resource`
// colon other services use) because luxd already gates ~30 call sites
// on these exact strings via id.HasScope; renaming them is a separate
// breaking change, not a registry edit.
var (
	LuxRead     = Scope{Name: "llm.read", Description: "Read LLM gateway usage, request feed, model catalog, and settings.", Category: "Lux"}
	LuxInvoke   = Scope{Name: "llm.invoke", Description: "Proxy upstream providers and manage your own provider keys, virtual keys, access profile, and hooks.", Category: "Lux"}
	LuxServe    = Scope{Name: "llm.serve", Description: "Expose a local model runtime (Ollama, vLLM, LM Studio, llama.cpp, MLX) through Lux over a reverse tunnel.", Category: "Lux"}
	LuxAdmin    = Scope{Name: "llm.admin", Description: "Org-wide LLM gateway custody: platform/org/env provider keys, model-catalog writes, org settings, other principals' profiles.", Category: "Lux"}
	LuxKeyAdmin = Scope{Name: "llm.keyadmin", Description: "Server-to-server admin to mint and revoke owner-scoped virtual keys.", Category: "Lux"}
)

func lux() []Scope { return []Scope{LuxRead, LuxInvoke, LuxServe, LuxAdmin, LuxKeyAdmin} }
