# POSIX Projection — Cross-Platform Questions

Status: **Design / routing.** The Linux coordinator owns the abstract
architecture ([posix-authority-model.md](posix-authority-model.md)). macOS and
Windows behavior is **not guessed here** — it is handed to native agents via the
briefs under [`docs/briefs/`](../briefs/). Per
[ADR 0026](../adr/0026-posix-authority-projection.md), where a platform cannot
faithfully project an authority, **`Unsupported ⇒ refuse` is preferred over
widening**. No macOS/Windows cell below may be promoted from "probe" to a
Faithful/Conservative/Unsupported class without native evidence feeding
[`refinement_matrix.toml`](../../formal/assurance/refinement_matrix.toml).

## Feasibility matrix

Classes: **F** Faithful, **C** Conservative, **U** Unsupported (⇒ refuse), **?**
Unknown (⇒ refuse), **probe→** hand to the named brief. Established in-repo facts
are given as a class; everything else is a probe.

| Abstract primitive | Linux | macOS | Windows |
|---|---|---|---|
| File read (canonical root) | **F** (Landlock) | **F** (Seatbelt) | **F** (AppContainer DACL) |
| File write (canonical root) | **F** | **F** | **F**, but write⇒read (E2) |
| Directory create/delete/rename | **F** | probe→ [macOS §5] | probe→ [win §4] |
| Lookup / namespace resolution | **C** (`openat2` design) | probe→ [macOS §5] | probe→ [win §4] |
| Execute (resolved image) | **C** / Interceptor (ld.so) | **F**, C for sh→bash (#318) | **?** allowlist inexpressible; F only deny-all |
| Net remote-host | **?** (netns proxy unbuilt) | **C** Advisory (egress proxy) | **?** |
| Net loopback | **C** (whole-interface widen) | **F** | **F** (loopback exemption) |
| Net deny-all (`net:none`) | **F** under `DenyDirect`; **?** under `LandlockOnly` | **F** | **F** (no InternetClient SID) |
| Metadata / inspect (`stat`) | **?** (Landlock no stat hook) | **?** ambient (ASM-MACOS-METADATA) | probe→ [win §3] |
| Descriptor derive (`dup`/reopen) | **C** (re-mediate reopen) | probe→ [macOS §2] | probe→ [win §1] |
| Descriptor inheritance across exec | **?** → target **F** (#319 `close_range`) | probe→ [macOS §6] | probe→ [win §1] |
| `SCM_RIGHTS` / IPC delegate | **?** (abstract-ns residual) | probe→ [macOS §2] | probe→ [win §9] |
| Cross-process signal / ptrace | **U** ⇒ refuse | probe→ [macOS §7] | probe→ [win §7] |
| `ioctl` / device | **U** ⇒ refuse | probe→ [macOS §7] | probe→ [win §8] |
| Object identity / canonicalization | **F** (E1 object-stability) | probe→ [macOS §5] | probe→ [win §4] |
| CID namespace binding (PosixNamespaceCID) | design (§6 model) | platform-agnostic | platform-agnostic |

## Open questions by platform (highest priority)

**macOS** (see [posix-macos-brief.md](../briefs/posix-macos-brief.md)):
1. Can Seatbelt confine `file-read-metadata` at all, or is metadata inherently
   ambient? (§1 — settles the `inspect` class on macOS.)
2. Enumerate child-drivable mach/XPC egress deputies beyond nsurlsessiond (E4).
   (§3 — bounds the deputy residual.)
3. What does a *faithful* (non-`verbatim`) Seatbelt `resolved_authority` require?
   (§4 — closes the I15-Partial gap.)

**Windows** (see [posix-windows-brief.md](../briefs/posix-windows-brief.md)):
1. Is a write-only ACE expressible, or does the DACL force write⇒read? (§2 — the
   E2 headline; feeds RC-SHA re-certification of ASM-WIN-DACL.)
2. Can any mechanism (WDAC?) express a non-empty exec allowlist under
   AppContainer? (§5 — currently `Unknown`.)
3. Do Windows HANDLEs give a faithful descriptor-as-capability model, and does
   AppContainer mediate handle-derived access? (§1.)

**Linux** (owned here, not a brief): the two promotions that move `?`→`F` are the
netns+veth egress fence (remote-host `net`) and pidfd-based process authority
(cross-process `signal`), both post-slice-1; and slice 1 itself (#319) moves
descriptor inheritance from `?` to the target `F`.

## Promotion rule

A `probe→` cell becomes a class only when a hostile-child native test on real
hardware, with a positive control distinguishing *denial* from *inability*,
lands and is referenced from `refinement_matrix.toml`. This is the same
"SKIP is not PASS" discipline the assurance gate already enforces
([`assumptions.md`](../../formal/assurance/assumptions.md)).
