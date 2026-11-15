import Machines.Device

/-!
Claims about the example Device table, written by hand. Each is a finite
check over the generated table, closed by `decide`, carried to every path
by a lemma of `Statemachine`. A change to the table that breaks a claim
fails the build.
-/

namespace Proofs.Device
open Machines.Device Statemachine

/-- A denied request is never approved: nothing follows `denied`. -/
theorem denied_never_approved (s : State) (r : Reaches machine .denied s) :
    s ≠ .approved := by
  have := machine.terminal_stays terminal_denied r
  subst this; decide

/-- Only an approved request is consumed. -/
theorem consumed_only_after_approval :
    ∀ s ∈ machine.states, State.consumed ∈ machine.next s → s = .approved := by
  decide

/-- Once approved, a request is never pending or denied again. -/
theorem approved_stays_decided (s : State) (r : Reaches machine .approved s) :
    s ∈ [State.approved, .consumed, .expired] :=
  machine.reaches_closed (by decide) r (by decide)

/-- Concurrent writers that check the state they land on keep the table,
whatever they read and in whatever order their writes land. -/
theorem guarded_writers_follow (ws : List (Write State)) (row : State) :
    Reaches machine row (ws.foldl machine.guarded row) :=
  machine.guarded_follows ws row

end Proofs.Device
