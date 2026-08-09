# ADR 0025 — Authority fidelity + content-addressed provenance (the 7-law spine)

- Status: Accepted (2026-08-09) — operator-approved plan; implementation stacked
- Date: 2026-08-09
- Refs: agent-bridle#317 (EnforcementFloor), the 39-row bounded-authority audit
  (`knowledge/board/2026-08-09_ab317-bounded-authority-audit-EVIDENCE.md`), the approved plan
  (`knowledge/board/2026-08-09_content-addressed-authority-provenance-PLAN.md`),
  companion ADRs in `agent-mesh/docs/decisions/` and `newt-agent/docs/decisions/`.

## Context

A 32-agent adversarial audit proved #317's `EnforcementFloor` closes only **INV-FLOOR**
(`strength ≥ floor`). Its admission `unenforceable_axis_in_report` (report.rs:676-704) has
**no resolved-scope operand**, so it cannot express **INV-BOUND** (`effective ⊆ authorized`).
Result: **19 confirmed violations** where a kernel-enforced *wider* scope is admitted on
strength alone (Seatbelt `sh`→`bash`; Landlock/rootfs `base_read_paths`/loader/stdlib; the
egress-proxy caveat *substitution before the floor check*; inherited non-CLOEXEC fds), plus a
**report/apply non-equivocation** class — admission analyzes `effective` (spawn.rs:534) while
the child is confined by a wider `mechanism_effective` (spawn.rs:550-555, 1003). Downgrading a
widened axis to a weaker `AxisEnforcement` does **not** make it safe; it hides scope-widening
inside the strength lattice. Lineage: this is Bazel REAPI's "worker read outside `input_root`"
— the fence must *be* a content-addressed closure so a widening is a different CID.

## Decision

Adopt content addressing throughout the authority path, governed by **law-minimalism** (the
full CID coverage is *generated* by seven terse laws, not maintained as special cases):

- **L1 IDENTITY** — an object's id = CID of its one validated canonical dag-cbor typed
  representation (published `content-addressable 0.1.0`; do **not** fork); typed domains can't
  be confused (`kind` tag in the hashed body + newtype). Canonical rule: decode → validate →
  normalize typed → re-encode → CID (never hash caller-supplied raw bytes).
- **L2 NON-EQUIVOCATION** — the object admission analyzed *is* the object applied:
  `CID(analyzed) == CID(applied)`. Spawn consumes one `AdmittedFence`; the separate
  re-derivation path is **deleted**, not merely CID-compared.
- **L3 BOUND** — admit iff per axis `effective ⊆ delegated ∪ authorized_runtime_closure`, the
  closure explicit/minimal/harness-disjoint; fidelity **computed** over a resolved-authority
  lattice (`ConcreteScope | CapabilityClass | Unbounded | Unknown`), never asserted.
- **L4 FLOOR** — every restricted axis meets its required strength (orthogonal to scope).
- **L5 PROVENANCE** — evidence binds the exact grant, fence, residual-set, process-tree, and
  session measured; other-session/stale can't satisfy.
- **L6 AUTHORIZATION** — authority only attenuates (`⊑`) unless an elevation carries a valid
  operator signature; a CID identifies, it never authorizes.
- **L7 FAIL-CLOSED** — unknown/missing/unverifiable/widened/mismatched/stale/unsupported ⇒ refuse.

**agent-bridle owns the native layer** (loosely-coupled/functionally-cohesive): `RuntimeClosure`
(distinguishing `ChildVisibleRuntimeAuthority` vs `HarnessOnlyAuthority` — `~/.newt`, operator
keys, OCAP store, permission log **never** child-visible), `EnforcementPlan`, native
`ResolvedFence` (per backend; references platform-artifact CIDs — Seatbelt profile, Landlock
plan, AppContainer capability set, rootfs tree), `AdmissionDecision`, `EnforcementEvidence`
(with a `Degradation` split `StrengthUnavailable | ScopeWidened{kernel_permits: capability-class}`,
a content-addressed `PlatformResidualSet{state: Active|Bounded|Gated}`, and a `ProcessTreeWitness`),
`ExecutionResult`. Bridle **projects** its native fence into a portable resolved-authority for the
mesh admission check; it **applies** the fence and **measures** the witness. The portable semantic
layer (`Authority`/`AuthorityId`, `Grant`/`GrantId`, the lattice, `ScopeRelation`, the pure
admission decision, the verifier contract) lives in **agent-mesh**; bridle never re-implements it.
Spawn API becomes `spawn(AdmittedFence)` — `spawn(Caveats, SandboxPolicy, EnforcementReport)` is
removed so the unsafe state is unexpressible.

## Consequences

- **#317 is NOT-READY** until L2+L3+L4 are live on the real admit/apply path. The strength-only
  theorem it currently ships is false under INV-BOUND. The merged resolution branch
  `fix/ab-per-axis-strength-floor@46f4324` stays green but does not merge to main until the
  fidelity path lands.
- The 19 confirmed sites are fixed **generically** (each falls out of L3), not by
  `if sh {Interceptor}` special cases.
- Honest limit registered: for a native mechanism, "resolved authority" is our **model** of the
  profile; where untested (loopback `127.0.0.1` vs `127/8`) it is a **registered residual**, not
  a proven fact.
- Enables the truthful OCAP-off/on parity the Terminal-Bench deliverable (newt `feat/psyche`)
  requires: an honest bounded OCAP-on lane whose task-needed authority is granted via the
  **explicit RuntimeClosure**, never via silent widening.
- Proof obligations: Lean for L1/L3/L4/L6-attenuation; TLA+ for L2/L5/L6-signature/L7 (model
  crash+restart as explicit actions — the buildfarm/Redis lesson). Never commit an unchecked spec.

---
Model: Claude Opus 4.8 (1M context) | Harness: Claude Code | Operator: Shawn Hartsock | Time: 15:09 EDT | Date: 2026-08-09
