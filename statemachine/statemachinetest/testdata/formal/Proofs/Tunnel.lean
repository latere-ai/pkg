import Machines.Tunnel

/-!
Claims about the example Tunnel table, whose states keep the case of the
values a column stores. Written by hand and closed by `decide`.
-/

namespace Proofs.Tunnel
open Machines.Tunnel Statemachine

/-- A retired tunnel never comes back online. -/
theorem retired_never_online (s : State) (r : Reaches machine .«Retired» s) :
    s ≠ .«Online» := by
  have := machine.terminal_stays terminal_Retired r
  subst this; decide

/-- Only a starting tunnel goes online. -/
theorem online_only_from_starting :
    ∀ s ∈ machine.states, State.«Online» ∈ machine.next s → s = .«Starting» := by
  decide

end Proofs.Tunnel
