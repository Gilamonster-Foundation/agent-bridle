# ADR 0013 — Tier-2 program-identity confinement (the trampoline close via a minimal rootfs)

- Status: Proposed (2026-06-30)
- Date: 2026-06-30
- Context: ADR 0011 shipped the Landlock **exec boundary** — a permitted binary
  cannot *directly* `execve` an un-granted tool (`find -exec curl`, payloads,
  shebangs, symlinks), and the read base was narrowed (D3 / #102) so the obvious
  `/usr/bin` corpus is not even readable. But ADR 0011 D2/D7 are explicit that this
  is the **boundary, not program identity**: with the library tree (`/usr/lib`)
  necessarily readable so dynamically-linked programs can load their `.so`s,
  **`ld.so` can `mmap`-exec any *readable* ELF** (Landlock has no `mmap` hook), and
  a *granted* interpreter runs arbitrary in-process code. Neither is an `execve`
  the `Execute` rule sees. So `agent-bridle` honestly reports the `exec` axis as
  `interceptor`, never `kernel`, and a strong principal **fails closed** on a
  restricted `exec` (ADR 0012). The remaining escape — running an un-granted
  program *as code* via the loader trampoline — has **no `fs_read`-allowlist
  close**, because *a readable ELF is a runnable ELF*. ADR 0011 D9 and ADR 0009 D2
  route this **program-identity** close to **Tier-2**. This ADR specifies it.
- **Extends ADR 0009** (fills in D2 — the micro-VM tier — and adds the lighter
  namespace-rootfs variant beneath it) and **ADR 0011** (turns "deferred to
  Tier-2" into a concrete mechanism + the one configuration where `exec` may at
  last be reported `kernel`, ADR 0011 D7). Governed by ADR 0002 (the meet lattice;
  this only *removes* reachable code, never widens authority) and ADR 0004 (axis
  honesty). Interacts with **SECURITY.md / #101** (the disable-unprivileged-userns
  hardening — see D4, a real tension this ADR resolves).
- Related issues: **#57** (the exec frontier — un-held for the boundary in #99;
  this is the identity close), #35 (Linux netns/`net` axis — the network half of
  the same jail), #50/#51 (the macOS/Windows tiers — D7), DESIGN §6.

## Question

The loader trampoline cannot be closed by *denying reads* — `/usr/lib` must be
readable for any dynamic binary to load, and any readable ELF can be `mmap`'d as
code. **How do we soundly confine program *identity* — "only the granted programs
run" — for the realistic dynamically-linked / multi-tool case, such that `exec`
can finally be reported `kernel` rather than `interceptor`?**

The answer is an **inversion**: stop trying to make un-granted code *unreadable*,
and instead make it *not exist* in the process's filesystem view. Confinement by
**construction of the namespace**, not allow-listing of reads.

## Decision

Run the confined work inside a **minimal, constructed rootfs** that *physically
contains only* the granted program binaries, their exact shared-library closure,
the dynamic loader, and the granted `fs_read`/`fs_write` data — and *nothing else
executable*. With no un-granted ELF present anywhere the process can reach,
`ld.so` has nothing to trampoline into and a shell-out has nothing to find: the
**readable set is, by construction, the granted set**. The same minimal rootfs is
deployed at two strengths (matching ADR 0009's ladder); both compose with the
Landlock fs rules *inside* the jail.

### D1 — Confine identity by what *exists*, not by what is *readable* (the keystone)

The ADR 0011 trampoline is unbeatable at the read-allowlist layer because
read-allow cannot distinguish "data" from "code" — every readable byte is a
candidate for `mmap(PROT_EXEC)`. The only sound close is to ensure the bytes of
un-granted programs are **absent** from the process's mount namespace. Absence is
checkable and total in a way a read rule is not: a strong principal's run is
`kernel`-confined on `exec` **iff** the only executables reachable in its rootfs
are the granted ones.

### D2 — The minimal rootfs: granted binaries + their closure + loader + data

Build, per grant (cached — D6), a read-only root tree containing exactly:

- the **resolved granted program files** (`resolve_exec_paths`, already in
  `sandbox.rs`), each at its real path;
- their **shared-library closure** — resolved the way the loader resolves it
  (`ld.so --list` / parsing `DT_NEEDED` + the search path), *not* a wholesale
  `/usr/lib` bind, so only the `.so`s the granted binaries actually need are
  present;
- the **dynamic loader(s)** (`LOADER_PATHS`);
- the curated **runtime data** a program reads but cannot execute (locale,
  timezone, CA bundles, `nsswitch`/`resolv.conf`) — these are data, not ELFs, so
  they do not reopen the trampoline;
- the granted **`fs_read` / `fs_write`** roots (bind-mounted ro/rw respectively);
- a minimal `/dev` (`null`,`zero`,`urandom`,…), `/proc` (the jail's own), `/tmp`.

Everything is bind-mounted **read-only** except the `fs_write` roots. The tree
contains **no `/usr/bin`, no `/bin`, no second interpreter** — so `find -exec`,
`grep -f /etc/shadow`, an `ld.so` trampoline, and a `system("curl")` all fail at
the most fundamental level: the target file is not there.

### D3 — Two deployment strengths, one rootfs (ADR 0009 ladder)

- **Tier-1.5 — mount-namespace rootfs.** `unshare(CLONE_NEWNS)` (+ a network
  namespace for the `net` axis, #35) → assemble the tree → `pivot_root` → drop
  into it, then apply the Landlock fs rules (now over a tiny tree) and spawn. No
  separate kernel; lowest overhead; the program-identity close without a VM.
- **Tier-2 — micro-VM** (Firecracker / Cloud Hypervisor / Kata; ADR 0009 D2). The
  *same* minimal rootfs as the guest image, booted under a separate kernel —
  strongest isolation (a guest-kernel compromise is still contained), at a
  ~100–150 ms boot cost. Required where the threat model includes kernel-level
  escapes or where KVM is available and the work is long-lived.

Both are selected behind the existing `best_available_sandbox()` seam (a new
`SandboxKind` per mechanism) with the same fail-closed `apply()` contract.

### D4 — Privilege model, and the unprivileged-userns tension (#101)

Building a mount namespace + `pivot_root` unprivileged needs a **user namespace**
(`CLONE_NEWUSER`) — which **directly conflicts with SECURITY.md / #101**, where we
recommend *disabling* unprivileged user namespaces to close the bind-mount escape.
This ADR resolves the tension explicitly:

- **Do not depend on unprivileged userns.** The Tier-1.5 rootfs is constructed by
  a small **privileged broker** (a setuid helper or a root-owned
  `agent-bridle-jaild` the host runs) that builds the namespace, drops all
  privilege (and `CLONE_NEWUSER`-isolates the uid map *after* construction), then
  `execve`s the granted program. This keeps the host's "unprivileged userns off"
  hardening intact while still giving the jail. (The broker is the trusted
  component; it is small, audited, and never runs agent-controlled code.)
- **The micro-VM (Tier-2) sidesteps host namespaces entirely** — the VMM builds
  the guest; no host userns is needed at all. On hardened hosts with userns off,
  Tier-2 is the path.
- **Fail closed:** if neither a broker nor a VMM is available, the backend reports
  `SandboxKind::None` for the identity axis and a strong principal is refused —
  never a silent drop to the Tier-1 boundary while *claiming* identity.

### D5 — Honesty: this is the one place `exec` becomes `kernel`

In a minimal-rootfs run, the per-axis report (#30) may finally set
**`exec → kernel`** — because the ADR 0011 D7 precondition ("no un-granted ELF is
reachable to trampoline into") is now *physically true*, not asserted. The report
distinguishes the modes: a Landlock-only boundary run stays `exec → interceptor`
(ADR 0011); a minimal-rootfs run is `exec → kernel`. The `noop_host_never_reports_kernel`
oracle and the exhaustive `SandboxKind` match (ADR 0004 D1) are preserved by
adding the new kinds, not by loosening the existing arms.

### D6 — A granted *interpreter* is still in-process arbitrary code

The rootfs closes program *identity* ("only the granted binaries run as
processes"). It does **not** make a granted interpreter safe: `python` in the jail
can still execute arbitrary *in-process* logic, bounded only by the jail's `fs`
(the granted roots) and `net` axes — there is no further `execve` for identity to
govern. So `exec → kernel` means "no un-granted *program* runs," **not** "the
granted program does only what you expect." Granting an interpreter remains the
strictest, highest-authority `exec` choice (ADR 0012 D8: `code` is the strictest
preset), and the report must not imply the interpreter's interior is constrained
beyond the fs/net jail.

### D7 — Construction cost, caching, and cross-platform

- **Cost / caching.** The library-closure resolution + tree assembly is the
  expensive step; cache the built rootfs by the content hash of the
  *(granted-binary-set + their resolved closure)*, so repeated runs of the same
  toolchain reuse the image. Tier-1.5 assembly is bind-mounts (cheap once
  resolved); Tier-2 adds the VM boot.
- **Cross-platform (ADR 0009).** The minimal-rootfs idea is Linux-shaped
  (`pivot_root` / a Linux guest). macOS and Windows reach program identity
  differently — Seatbelt cannot exclude binaries by absence, so macOS identity is
  a curated app bundle + Seatbelt `process-exec*` rules (#50 follow-up), and
  Windows uses an AppContainer with an explicit allowed-image policy (#51). This
  ADR specifies the Linux close; the per-OS identity story is tracked under ADR
  0009's tiers.

## Consequences

**Positive**

- **Closes the loader/interpreter trampoline** for the realistic case — the one
  escape ADR 0011 could not — by construction, not by an unwinnable read rule.
- **Unlocks an honest `exec → kernel`** (D5): the strongest claim the leash can
  make about exec, true because un-granted code is absent, not merely denied.
- **Composes** with the shipped Landlock fs rules (they now govern a tiny tree)
  and with the `net` namespace (#35) — one jail, all axes.
- **Respects the #101 hardening** (D4): no dependence on unprivileged userns.

**Negative / risks**

- **A new trusted component** (the privileged broker) or a **VMM dependency** —
  both heavier than the in-process Landlock path; the broker must be small,
  audited, and never execute agent-controlled logic.
- **Library-closure resolution is fragile** (`dlopen`/`ctypes` loads are
  undecidable to enumerate statically) — a missing `.so` is a *deny-of-function*
  (the program fails to load), not a safety hole, but it needs a runtime canary /
  fallback to a wider closure for known-dynamic loaders.
- **Per-grant construction cost** (mitigated by caching, D6); a poor cache key
  silently rebuilds.
- **Not a guarantee about a granted interpreter's behavior** (D6) — must not be
  marketed as such.

## Options considered and rejected

- **Read-allowlist narrowing alone** (ADR 0011 D3 / #102) — rejected as the
  *identity* close: it shrinks the corpus but a readable ELF stays runnable, and
  `/usr/lib` must remain readable. Kept as the Tier-1 defense-in-depth beneath
  this.
- **seccomp `execve` deny** — rejected (per #57's seccomp findings): a pre-spawn
  filter cannot express "run P but P execs nothing" (the spawn *is* an `execve`),
  and it cannot govern the `mmap`-trampoline at all. seccomp's value is the
  mount/namespace-family deny, orthogonal to identity.
- **gVisor / a full container runtime** (containerd, bubblewrap) — rejected as the
  *default*: gVisor is Linux-syscall-bound (ADR 0009) and a full runtime is a
  large dependency + attack surface; the minimal hand-built rootfs is the smallest
  thing that closes identity. A container runtime may be an *embedder* choice.
- **Unprivileged-userns mount namespace as the primary path** — rejected (D4): it
  contradicts the #101 hardening. The privileged broker / micro-VM are the
  host-hardening-compatible paths.
- **Claiming `exec → kernel` for a Landlock-only boundary run** — rejected
  (ADR 0011 D2): the trampoline makes it false; `kernel` is reserved for the
  minimal-rootfs mode (D5).

## Follow-ups (tracking issues)

- **#57** — implement Tier-1.5 (the namespace-rootfs + broker) as the first
  identity close; the `exec → kernel` report arm (D5) lands with it.
- **#35** — the `net` namespace is the same jail's network half; build them
  together.
- **ADR 0009 / #50 / #51** — the micro-VM (Tier-2) deployment and the macOS/Windows
  identity stories.
