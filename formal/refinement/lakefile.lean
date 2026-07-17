import Lake
open Lake DSL

-- Tier-3 REFINEMENT project: proves the extracted (Charon/Aeneas) Rust of
-- `agent-bridle-ceremony` satisfies the Authority.lean algebraic laws.
--
-- This tier is HEAVY (it pulls the Aeneas Lean backend + mathlib), unlike the
-- fast, mathlib-free `formal/` project. It is deliberately NOT in the mandatory
-- pre-push gate; run it on a machine with the toolchain via `just check-refinement`.
--
-- `aeneas-lean` is a machine-local symlink to `<aeneas>/backends/lean`,
-- gitignored so no absolute path is committed. Create it with `./setup.sh`
-- (honours `AENEAS_LEAN_LIB`). See README.md and docs/TOOLCHAIN.md §2.
require Aeneas from "aeneas-lean"

package «ceremony-refinement» where
  leanOptions := #[⟨`maxHeartbeats, (1000000 : Nat)⟩]

@[default_target]
lean_lib AgentBridleCeremony

@[default_target]
lean_lib Refinement
