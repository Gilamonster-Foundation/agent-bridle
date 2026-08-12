# ADR 0026 — POSIX as a projection of Bridle authority

- Status: **Proposed** (2026-08-11)
- Date: 2026-08-11
- Context: Bridle confines a child by *composing* per-OS mechanisms (Landlock,
  seccomp, Seatbelt, AppContainer) behind one `Caveats` algebra. The recurring
  question — "can we give an agent a POSIX-shaped world that contains exactly its
  delegated authority?" — has, until now, lived only as prose in
  [legibility-and-the-opaque-box.md](../design/legibility-and-the-opaque-box.md)
  (the "handle, never ambient pathname" target) and as the open descriptor-hygiene
  gap **#319**. This ADR is the architecture-before-implementation gate: it
  decides whether a *POSIX authority projection* is the right abstraction before
  any libc interposition, syscall broker, `LD_PRELOAD`, ptrace, FUSE, or
  seccomp-notify enforcement is written.
- Governed by / harmonizes with: **ADR 0002** (`Caveats` meet-semilattice, the
  unforgeable `ToolContext`, no `join`/`widen`), **ADR 0020** (authority as a
  product meet-lattice), **ADR 0009** (cross-platform confinement strategy),
  **ADR 0011** (Landlock exec-axis co-confinement), **ADR 0012** (fence strength
  as a GLB), **ADR 0023** (three-tier proof discipline — a claim with no tier is
  prose).
- Scope: the *authority architecture* of a POSIX projection — object grain,
  descriptor-as-capability, namespace resolution, the CID chain, the security
  theorems, and the platform-projection obligations. It does **not** authorize an
  implementation; a GO here authorizes proposing an implementation phase.

Companion design: [posix-authority-model.md](../design/posix-authority-model.md).
Machine-checked: [`formal/Ceremony/Posix/Machine.lean`](../../formal/Ceremony/Posix/Machine.lean),
[`formal/tla/PosixAuthority.tla`](../../formal/tla/PosixAuthority.tla).

## Question

Should Bridle build a POSIX execution model as a *projection* of its authority
algebra — and if so, what is the smallest first slice, and does the abstraction
survive adversarial review?

## Decision

**GO WITH A REVISED (NARROWER) ABSTRACTION.** The authority architecture survives
review sufficiently to propose an implementation phase, on three conditions:

1. **The projected surface is "object + descriptor authority," not "POSIX."** We
   do not build a POSIX compatibility layer. We build the projection of Bridle
   authority onto three object operations — *authorized namespace resolution
   (open), descriptor derivation (dup/openat/reopen), and spawn/inheritance* —
   and let a POSIX-shaped namespace be the *interface* over that, never the
   security boundary. This matches the model's proven core (§4-§7 of the design
   doc) exactly and refuses the parts of POSIX that cannot be mediated honestly
   (`ioctl`, arbitrary IPC) by resolving them to `Unknown ⇒ refuse`.

2. **The first executable slice is issue #319, Linux-first.** Close ambient file
   descriptors on spawn (`close_range` in a launcher path) and model descriptor
   inheritance, so the descriptor-as-capability claim becomes *true on the real
   path* rather than aspirational. This is the smallest step that discharges the
   model's load-bearing invariant (`fds ⊑ effective` across `exec`), it already
   has an issue and a design doc, and it needs no new authority class.

3. **No mediation mechanism merges without its refinement evidence.** Per ADR
   0023 and `formal/assurance`, each projected operation lands with a
   hostile-child test and an `ASM-POSIX-*` ledger row, or it stays `Unknown`.

A GO does **not** authorize production libc interposition, a syscall broker, or a
`bridle-run` launcher advertised as secure. Those require a subsequent explicit
decision after the #319 slice proves the seam.

### Why "revised," not plain GO

The user's stated hypothesis — *object/descriptor authority + authorized
namespace resolution + spawn/descriptor inheritance, Linux-first* — is correct
and we adopt it. The revision is to narrow *further*: name the deliverable
"descriptor-authority projection," not "POSIX," so that scope creep toward
libc-completeness is structurally discouraged and the honest refusals (`ioctl`,
metadata, cross-process signal) are visible as first-class `Unknown` rows rather
than gaps in a "POSIX sandbox."

## Why bridle-POSIX may be the wrong abstraction

Written to be allowed to change the decision. Each objection is tagged ACCEPT
(a real limit we fold into scope), MITIGATE (real, but the design answers it),
REJECT (does not hold), or UNRESOLVED.

1. **POSIX is too semantically broad to mediate honestly.** — **ACCEPT.** This is
   why the decision renames the deliverable to "descriptor authority" and pushes
   `ioctl`/arbitrary-IPC to `Unknown ⇒ refuse`. We do not mediate POSIX; we
   mediate three operations and *present* POSIX.
2. **Existing OS mechanisms cannot faithfully project the authority.** —
   **MITIGATE.** True for several axes (Linux `exec` is `Interceptor` not
   `Kernel` — the ld.so trampoline; remote-host `net` is advisory). The model
   already reports these as sub-`Kernel`/`Unknown` rather than claiming them; the
   matrix makes each honest. Faithful projection exists for the fs core on all
   three platforms today.
3. **Descriptor-as-capability reasoning breaks in important cases.** —
   **MITIGATE.** `/proc/self/fd` reopen, `O_PATH` upgrade, and `openat("..")`
   genuinely break it (§4). The design closes them by re-mediating reopen/lookup
   against `effective` (never trusting fd-derivation) and requiring
   `openat2(RESOLVE_BENEATH)`. The residue is #319 (ambient fds) — scoped as
   slice 1.
4. **Cross-platform semantics become lowest-common-denominator mush.** —
   **REJECT.** The design does not take an intersection of platform semantics; it
   takes the *authority* projection and lets each platform report Faithful /
   Conservative / Unsupported / Unknown per axis (the existing `refinement_matrix`
   pattern). A platform that cannot enforce an axis refuses; it does not drag the
   others down.
5. **The model duplicates Capsicum without sufficient advantage.** —
   **MITIGATE.** Capsicum is the acknowledged ancestor (§Related systems). The
   distinguishing additions are real: a portable authority algebra with a
   *content-addressed* admit→apply binding, per-axis honest-strength reporting,
   and fail-closed refusal on unprojectable axes — none of which Capsicum's
   capability-mode provides, and Capsicum is FreeBSD-only.
6. **Enforcement complexity increases attack surface.** — **ACCEPT.** Every
   mediation mechanism is new attack surface. The mitigation is the no-broker
   decision: slice 1 is `close_range` + `openat2` flags (kernel primitives, no
   new daemon), not a syscall-notify broker. A broker is a *later, separate*
   decision precisely because of this objection.
7. **Agent workloads don't need enough POSIX compatibility to justify this.** —
   **UNRESOLVED.** We have no measured corpus of what agent tool-calls actually
   require of POSIX. This is the strongest objection. The #319 slice is cheap
   enough to proceed without resolving it, but a **research spike to characterize
   the real syscall/opcall footprint of agent workloads** is a named follow-up
   before any broker is proposed.
8. **A narrower "portable execution-authority ABI" would beat POSIX.** —
   **MITIGATE, and partly adopted.** This is essentially the revised decision:
   the *security* surface is a narrow execution-authority projection; POSIX is
   only the *presentation*. We reject building a POSIX security model; we keep a
   POSIX-shaped interface because agents run existing tools that speak it.
9. **Kernel/deputy behavior defeats complete mediation.** — **ACCEPT (bounded).**
   Ambient deputies (macOS mach/XPC, E4; Linux ld.so; setuid helpers) can perform
   effects on a child's behalf. The model does not claim to close all deputies;
   it claims complete mediation *of the projected operations* and reports deputy
   channels as `Unknown`. E4 is a live, registered residual, not a solved
   problem.
10. **CID provenance adds complexity without preventing real attacks.** —
    **REJECT for the minimum set, ACCEPT for the rest.** The
    analyze-one/apply-another substitution on the *namespace* is a real attack the
    PosixNamespaceCID closes (§6); the AppliedFenceCID already exists and pays for
    itself. The deferred CIDs (Grant/Plan/Result) are correctly called out as
    aesthetics-for-now and *not* built.

**Net:** two ACCEPTs fold into scope (broad-POSIX and attack-surface → narrow to
descriptor authority, no broker in slice 1), one UNRESOLVED becomes a named spike
(workload footprint), the rest are answered by the design. No objection is fatal;
several reshape the scope, which is why the verdict is GO-WITH-REVISION.

## Related systems (what to steal / reject / add)

- **Capsicum** (FreeBSD; `cap_enter()` + capability-bearing descriptors,
  `openat`-only). **Steal:** capability mode's core discipline — once entered, no
  global namespace, only descriptor-relative lookup. **Reject:** its all-or-nothing
  process-wide mode switch and FreeBSD-only reach. **Add:** a portable authority
  algebra, per-axis honest-strength reporting, and the content-addressed
  admit→apply binding.
- **Linux Landlock.** **Steal:** path-beneath rulesets as the fs projection (in
  use). **Reject:** treating its absence of a net-address rule or mmap hook as
  "good enough" — the model reports those as `Advisory`/`Interceptor`. **Add:**
  the composition with seccomp (io_uring/socket deny) that Landlock alone lacks.
- **seccomp.** **Steal:** syscall-family denial as a *floor* under Landlock (E3).
  **Reject:** seccomp-as-policy-language (a raw allowlist is not authority
  mediation — the exact anti-pattern this ADR forbids). **Add:** nothing; seccomp
  is a mechanism, not a model.
- **pledge/unveil (OpenBSD).** **Steal:** `unveil`'s "the process sees only what
  was unveiled" — precisely the projected-namespace goal. **Reject:** `pledge`'s
  coarse promise categories (they are a fixed taxonomy, not an attenuable
  algebra). **Add:** attenuation and delegation the promise model has no carrier
  for.

Is Bridle's distinguishing combination real? The combination *portable authority
algebra + attenuation + native enforcement projection + fail-closed floor +
content-addressed provenance + execution evidence* is not offered by any single
system above. That is a genuine contribution claim, and it is testable — not a
novelty assertion — because each element already has code or a proof in-repo.

## Consequences

**Crate boundary (evaluated, not committed).** Prefer folding the abstract model
into `agent-bridle-core` (the repo's bias: core owns all authority; the facade
owns nothing). Introduce `agent-bridle-posix` **only if** the object/descriptor
model grows a dependency or security boundary that core should not carry. Defer
`agent-bridle-posix-linux`, `-darwin`, `-windows`, a `bridle-run` launcher, and
any `agent-bridle-libc` compatibility layer to post-slice-1 decisions. Slice 1
(#319) needs no new crate — it is a `ConfinedCommand` change plus an `openat2`
policy in `agent-bridle-core`.

**Open decision (the mesh fork).** Whether descendant attenuation wires in the
unused `agent-mesh-protocol` `Grant`/`Derivation`/`verify_chain` chain, or is
modeled at the POSIX grain, is deferred to the slice-1 design — recorded here so
it is not re-litigated as new.

**Positive.** The projection reuses the sovereign algebra unchanged; the honest
refusals (`ioctl`, metadata, cross-process signal) are visible, not hidden; the
first slice is small, issue-backed, and discharges the load-bearing invariant.

**Negative / residual.** The workload-footprint objection (#7) is unresolved and
gates any future broker. Deputy channels (E4, ld.so) remain `Unknown`. The
descriptor-as-capability claim is aspirational until #319 lands.

## Alternatives considered

- **NO-GO.** Rejected: the target already exists as prose and an open issue; the
  authority algebra and three of the four platform projections already exist; the
  cost of the first slice is bounded. Declining would leave #319 (a real ambient
  authority gap) unaddressed.
- **Plain GO on "POSIX."** Rejected: invites libc-completeness scope creep and
  would pressure the honest `Unknown` refusals into broad allowlists — the
  anti-pattern ADR 0002/0023 exist to prevent.
- **RESEARCH SPIKE only.** Partially adopted: the workload-footprint spike (#7) is
  named as a prerequisite for a *broker*, but is not required for the #319 slice,
  which stands on the existing design and issue.
