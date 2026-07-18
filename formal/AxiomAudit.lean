import Ceremony
import Tests
import Lean.Elab.Command

/-!
# F-233-06 — machine-readable proof-integrity audit

`Gate.lean` scans source *text* for the forbidden proof-escape words. That is cheap
hygiene but blind to what a proof actually DEPENDS on: an imported postulate, an
unsafe declaration, or the escape term reachable through a dependency edge is
invisible to a substring scan. This module closes that gap.

At build time it walks every theorem under the audited namespaces in the
environment, collects the postulates each proof transitively relies on
(`Lean.collectAxioms`), and **fails the build** if any lies outside the permitted
base. `lake build` elaborates this file, so `just check-formal`, the pre-push
hook, and CI all enforce it with no extra command — this is the semantic
counterpart the audit rider (F-233-06) asked for, complementing the text scan.

Extending `permittedAxioms` is a DELIBERATE proof-obligation review — edit it on
purpose, never by reflex.
-/

open Lean Elab Command

namespace AxiomAudit

/-- The only postulates the security proofs may rest on: propositional
    extensionality and quotient soundness (Lean's standard logical base). Notably
    ABSENT: `Classical.choice` (the proofs are constructive) and the escape term
    that unfinished proofs desugar to (its presence here would mean a hole slipped
    through). -/
def permittedAxioms : List Name := [``propext, ``Quot.sound]

/-- Namespaces whose theorems constitute the audited security surface. -/
def auditedRoots : List Name := [`Ceremony, `Tests]

/-- Audit a user-facing theorem (skip compiler-internal helpers). -/
def isAudited (name : Name) : Bool :=
  !name.isInternalDetail && auditedRoots.any (fun r => r.isPrefixOf name)

run_cmd do
  let env ← getEnv
  let mut audited : Nat := 0
  let mut violations : Array (Name × Name) := #[]
  for (name, info) in env.constants.toList do
    match info with
    | .thmInfo _ =>
      if isAudited name then
        audited := audited + 1
        let deps ← liftCoreM <| collectAxioms name
        for d in deps.toList do
          unless permittedAxioms.contains d do
            violations := violations.push (name, d)
    | _ => pure ()
  if violations.isEmpty then
    logInfo m!"proof-integrity audit: {audited} security theorems, all within the permitted base {permittedAxioms}"
  else
    let lines := violations.toList.map (fun (t, d) => s!"  {t} depends on {d}")
    throwError "proof-integrity audit: {violations.size} off-base dependency(ies):\n{String.intercalate "\n" lines}"

end AxiomAudit
