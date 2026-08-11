# Assumption ledger (Phase 8) — PROVED vs EMPIRICALLY ESTABLISHED

**The one rule this layer exists to keep honest:**

> FORMAL METHODS PROVE OUR MODEL.
> NATIVE EVIDENCE PROVES THAT THE OPERATING SYSTEM REFINES OUR MODEL.

Lean and TLA+ prove properties of Bridle's **model** under stated premises. They
do **not** prove Landlock, seccomp, Seatbelt, AppContainer, ACLs, or any kernel
implementation correct. Every place the model touches an OS fact, that fact is an
**assumption** discharged by a native hostile-child test — recorded here, never
buried in a theorem as an unquestioned `axiom` (the Lean gate forbids the literal
keyword precisely so no OS premise can masquerade as a proof).

Each assumption below is referenced by `premise = "ASM-…"` in `manifest.toml`.

---

## PROVED (mechanically, axiom-clean)

These hold in the model with no OS premise. Checked by `lake build` +
`lake exe formalGate` + `AxiomAudit` (188 theorems within `{propext, Quot.sound}`)
and by TLC over `AuthorityLifecycle.tla`.

| # | Property | Where |
|---|---|---|
| P1 | `within` is a partial order (refl on non-Unknown, trans, antisymm); union is monotone | `within_refl/within_trans/within_antisymm/within_union_left` |
| P2 | Admission is sound and refuses every widening (Superset) | `admission_sound/no_silent_widening/widening_refused`; TLA T2/T3 |
| P3 | **GIVEN** the Windows projection premise, `write ⊄ read ⇒ resolved.read ⊄ delegated.read ⇒ refuse** | `windows_write_implies_read_widening/windows_unrepresentable_narrowing_rejected` |
| P4 | Runtime closure cannot be hidden — added authority must widen the bound visibly | `runtime_closure_not_hidden`; TLA T2 |
| P5 | Unknown fails closed (axis or closure) | `unknown_never_admissible/unknown_closure_never_admissible`; TLA T4 |
| P6 | No execution before admission | TLA T1 |
| P7 | Descendant non-escalation **in the modeled transition** | TLA T5 |
| P8 | Provenance continuity **in the model** (Cid(x)=x, uninterpreted) | TLA T7 |

Note on P3 phrasing — the theorem is literally *"GIVEN WindowsProjectionSemantics,
Bridle admission refuses the narrowing."* The premise is a **hypothesis argument**
(`hproj`), not an asserted fact. That is the whole point: the proof is about the
consequence, the OS fact is quarantined below.

---

## EMPIRICALLY ESTABLISHED (by native evidence, NOT proved)

These are the premises the proofs stand on. Each is a claim about an actual OS,
discharged by a hostile-child test — and only as strong as that test. If a test
is SKIPPED (unsupported host) it establishes **nothing** (see the honesty note).

| ID | Assumption | Discharged by | Status |
|---|---|---|---|
| **ASM-WIN-DACL** | The aclaunch AppContainer DACL grants **content read** on every `--fs-write` path (`FILE_GENERIC_READ_WRITE`, main.rs:476) — i.e. the projection premise of P3 actually holds on Windows. | `agent-bridle-aclaunch/tests/kernel_proofs.rs::fs_write_grant_confers_read_e2` (write-only path readable; icacls records the AppContainer SID mask `(R,W)`) | **landed on main @ ef74ee2** (native probe under strict `BRIDLE_REQUIRE_APPCONTAINER`); **NOT RC-certified** — must re-run on the frozen RC SHA (ancestor-SHA evidence is not final RC evidence) |
| **ASM-WIN-ENV** | On Windows the ambient parent environment is cleared before `aclaunch`, so an undelegated secret does not reach the child (#323). | `agent-bridle-tool-shell/tests/windows_env_isolation.rs` (passes on real Windows 11) | established (#338 branch) |
| **ASM-INHERIT** | seccomp / Landlock / Seatbelt / AppContainer actually preserve the confinement boundary across a real **gen-2** grandchild. | linux `real_spawn.rs` + `child_network_seccomp_real.rs`; win `kernel_proofs.rs:222`; macOS `process-exec*` (child-grain) | linux+win established; macOS gen-2 partial |
| **ASM-SECCOMP-IOURING** | The seccomp floor denies the io_uring primitive so `net:none` is not bypassable off-box (E3). | `child_network_seccomp_real.rs` (needs an explicit io_uring probe — see the E3 review) | **residual: probe not yet landed** |
| **ASM-MACOS-METADATA** | macOS `file-read-metadata` observability is ORTHOGONAL to content `fs_read` and is a registered residual — it must NOT be modeled as content authority. | `seatbelt_floor_evidence.rs` (content denied, metadata ambient) | established as a residual |
| **ASM-CID** | Content CIDs are attached to runtime authority-bearing objects (grant/plan/fence/evidence). **Today they are NOT** — CID machinery is HELD in the ceremony P1 layer. P8/PROVENANCE-CONTINUITY is therefore a MODEL property only, not a wired runtime guarantee. | (unwired — Phase-1d freeze) | **held** |

### Release-certification rule (enforced by validate.sh)
A claim may be marked `status = "proved"` (release-certified) **only if it does not
depend on** any of: a **missing** evidence reference; an evidence item marked
**pending / unsupported / UNDISCHARGED**; or a **SHA/CID that does not identify the
artifact actually tested** (a placeholder `held:` / `TBD` CID, or an `impl_sha`
that is not the RC SHA under `--rc`). Native evidence that only exists on an
ANCESTOR SHA (e.g. `main` before the RC is cut) is NOT final RC evidence, so such
claims stay `partial` until they re-run on `BRIDLE_RC_SHA`. WIN-E2-WRITE-READ is
therefore `partial`, not certified. The theorem is never weakened to make the
manifest green.

### Honesty note — SKIP is not PASS
The native tiers self-skip where the mechanism is unavailable (no Landlock, no
`sandbox-exec`, no AppContainer). A skipped test establishes **nothing**; it must
not be reported as evidence. Windows CI already forces fail-not-skip via
`BRIDLE_REQUIRE_APPCONTAINER`; the Linux tests genuinely run on gnuc. Any claim
whose only native tier was skipped stays `partial`/`held`, never `proved`.

---

## What this layer explicitly does NOT claim
- It does **not** claim Lean/TLA+ prove AppContainer, Seatbelt, Landlock, seccomp,
  or ACLs secure.
- It does **not** claim the runtime chain is content-addressed end-to-end (ASM-CID).
- It does **not** upgrade a SKIPPED native test into evidence.
