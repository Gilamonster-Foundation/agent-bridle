# ADR 0014 — macOS Seatbelt exec axis (the sibling of ADR 0011, closed without a backstop)

- Status: Accepted (2026-06-30)
- Date: 2026-06-30
- Context: The macOS `SeatbeltSandbox` (`sandbox.rs`, ADR 0006 / ADR 0009) confines
  the `fs_write` and `fs_read` axes via an SBPL profile applied through
  `sandbox-exec(1)`, and (#50 follow-up, PR #96) kernel-denies **all** egress when
  `net` is empty. The **`exec` axis was left ambient** (`(allow default)` covers
  `process-exec*`), with the per-axis report (#30, ADR 0004 D1) hardcoding
  `exec → Interceptor` (`report.rs`) — the same held frontier ADR 0011 addresses
  for Linux/Landlock (#31/#57). This ADR closes it for macOS.
- **Extends ADR 0011** (the Linux exec-axis analysis) by answering the *same*
  question for the macOS backend, and **ADR 0004** (un-holds D2's `exec` axis for
  Seatbelt). **Governed by** ADR 0002 (the combined profile only ever *denies
  more*, so `effective ⊑ granted` is undisturbed — no new mint site, no new gate)
  and **ADR 0006/0009** (per-OS L3; capabilities differ per backend so the
  engaging condition and the honest report differ too).
- Related issues: **#57** (the `exec` frontier — closed here for macOS at kernel
  grain), #31 (the un-stub gate / honest report arm), #30 (the per-axis report's
  `exec` arm), #50 (the Seatbelt backend this extends).

## Question

ADR 0011 proves that on Linux a Landlock `Execute` allow-list **cannot** honestly
report `exec → Kernel` at program-identity grain, because of one structural fact:
`ld.so` converts any `READ` right into an `EXECUTE` capability (the loader
trampoline), and Landlock has no `mmap(PROT_EXEC)` hook — so the *readable* set is
the *runnable* set. Linux must therefore pair Landlock with a **seccomp-BPF
backstop** (ADR 0011 D4) to deny `execve`/`execveat` and the mount/namespace
family, and even then declares a granted interpreter `exec ≡ All`.

**Does the same limitation bind the macOS Seatbelt backend — i.e. does macOS also
need a second kernel mechanism to honestly confine `exec`, and must it likewise
surrender on the loader trampoline and on granted interpreters?**

The answer is **no**: macOS closes the `exec` axis — *including the interior, the
loader trampoline, and the interpreter case* — with **`process-exec*` alone**, no
backstop, because the two escape classes that defeat Landlock are **structurally
closed by the platform**. This ADR records the empirical proof, ships the exec arm
of the profile, and reports `exec → Kernel`.

## Empirical findings (macOS 26.5.1 / Apple Silicon, verified on-host)

All run live through `sandbox-exec` and are encoded as the `BRIDLE_REQUIRE_SEATBELT`
proof sweep in `sandbox.rs` so CI re-verifies them on every change.

1. **`process-exec*` governs the confined process's own launch and every child
   exec.** Under `(deny process-exec*)`, the wrapped target's launch itself is
   `EPERM` unless allow-listed; once a granted program runs, *its* `execve` /
   `posix_spawn` of any unlisted binary is kernel-denied (`/usr/bin/false` →
   status 127, "operation not permitted"). This is the **interior** grain — what a
   pre-spawn argv check (`check_exec`) and the Linux Landlock `Execute` hook reach,
   but *natively covering children*.

2. **Path-grained allow-list works at the interior.** `(allow process-exec*
   (literal X)(literal Y))` permits exactly X, Y; everything else, including a
   granted shell's children, is denied. = `exec:Only{set}`.

3. **The loader trampoline is closed.** A granted interpreter (`perl`) under
   deny-exec **cannot** `exec("/usr/bin/true")` (direct) **nor**
   `exec("/usr/lib/dyld", "/usr/bin/true")` (trampoline) — both are governed
   `process-exec`s, and `dyld` is not allow-listed. Unlike Linux, **the loader is
   mapped in-kernel during the single `execve` of the main binary**, so there is
   no *standing* execute-allow-listed loader entry an attacker can re-invoke. This
   is the macOS structural difference from `ld.so`.

4. **`mmap(PROT_EXEC)` read-as-code is closed by hardware W^X + code signing.**
   Anonymous `RWX` mmap is denied (`EPERM`); `mprotect` `RW→RWX` is denied;
   file-backed `mmap(PROT_EXEC)` of an arbitrary readable Mach-O is denied
   (`EPERM`). A non-JIT-entitled process cannot make writable memory executable nor
   map arbitrary data as code. **"The readable set equals the runnable set" — the
   fact that forces the Linux seccomp filter — does not hold on macOS.**

5. **Positive control / no deny-of-function.** An allow-listed dynamically-linked
   binary (`curl`) still loads its dylibs (the kernel-trusted dyld path is not
   gated by the exec allow-list) and runs (`curl --version`). Shebang scripts
   require their interpreter to *also* be granted (interpreter resolution is
   governed), matching admission semantics.

## Decision

Ship the `exec` arm of the Seatbelt profile and report `exec → Kernel` when it is
restricted under an active Seatbelt backend. No backstop mechanism is added —
Findings 3 and 4 show the platform already closes what Linux needs seccomp for.

### D1 — Emit `(deny process-exec*)` + a resolved allow-list

When `effective.exec` is `Only(_)`, `seatbelt_profile` appends
`(deny process-exec*)` and re-allows exactly the granted programs as
`(allow process-exec* (literal <resolved-abs-path>))`. SBPL is last-match-wins, so
the trailing allow overrides the deny. The wrapper engages on a restricted `exec`
axis even when no fs/net axis is restricted (`restricts_exec` joins the
`command_prefix` / `effective_sandbox_kind` engage condition).

### D2 — Resolve grants to canonical absolute paths through a *fixed trusted* PATH

The kernel matches `process-exec` against the **resolved** path of the exec target,
so each grant becomes a realpath (`resolve_exec_targets`): an **absolute** grant is
canonicalized and honored verbatim; a **bare name** is resolved against a fixed
trusted system PATH (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`) — never the ambient
`$PATH` (ADR 0011 D5's pin), so a binary planted earlier on a caller's `$PATH`
cannot widen the kernel allow-list, and a basename collision outside the trusted
dirs is not honored. A relative or unresolvable grant is **dropped** — it cannot
anchor a rule, so the program stays denied (fail-closed). This keeps the kernel
allow-list exactly as permissive as admission's basename match, and no looser.

### D3 — Fail closed: an empty/unresolvable grant denies *all* exec

`exec:none` (empty `Only`) and a grant that resolves to nothing emit the deny with
**no** re-allow — every exec, including the wrapped program's own launch, is
denied. The axis is never silently ambient.

### D4 — Honesty posture: `exec → Kernel` under Seatbelt, and why interpreters keep it

`enforcement_report`'s `exec` arm becomes a function of the active backend
(kept compile-exhaustive over `SandboxKind`): **`Kernel`** under `Seatbelt` when
`exec` is restricted; **`Interceptor`** under `Landlock` (its exec axis is held —
#31/#57), `AppContainer` (not wired this increment), and `None` (the
`noop_host_never_reports_kernel` oracle still holds). The coarse `sandbox_kind`
stays the **minimum** claim.

**The key divergence from ADR 0011 D6:** Linux must declare a granted interpreter
`exec ≡ All` because the loader trampoline lets `python` run `curl`. On macOS that
trampoline is closed (Findings 3–4), so a granted interpreter **still respects the
exec boundary** — it cannot run a binary outside the granted set — and the
`exec → Kernel` claim is honest for the *boundary* ("no binary outside the set
executes"). The interpreter's *interior logic* remains unconfined on the **fs/net**
axes (which govern it), not the exec axis; the exec claim is about *which binaries
spawn*, and that holds. The one residual: a JIT-entitled interpreter can make
executable memory for its **own** JIT — in-process code, confined to the fs/net
fence — not a different on-disk binary; the exec-axis identity claim is intact.

### D5 — `process-exec*` is the whole mechanism; no seccomp analog

Because `process-exec*` is checked at the kernel for the confined process and all
descendants, and the two non-`execve` code-entry paths (loader trampoline,
`mmap(PROT_EXEC)`) are platform-closed, macOS needs **no** second filter. There is
no `memfd`/`fexecve` analog reachable without an `execve` that is already governed,
and macOS has no unprivileged user-namespace / bind-mount to re-point a read tree
(the escapes that force ADR 0011 D4's mount/namespace seccomp deny).

## Bypass vectors and their disposition

| Vector | Disposition on macOS |
|---|---|
| `find -exec curl` / direct child `execve` of an unlisted binary | **Closed** — `process-exec*` denies it at the interior (Finding 1). |
| Loader trampoline (`dyld TARGET`, `perl -e 'exec("…dyld",…)'`) | **Closed** — `dyld` exec is itself a governed `process-exec`; no standing loader entry (Finding 3). Contrast Linux: `ld.so` must be Execute-allow-listed. |
| `mmap(PROT_EXEC)` read-as-code (anon shellcode or file-backed Mach-O) | **Closed** — hardware W^X + code signing deny it (Finding 4). Contrast Linux: no Landlock `mmap` hook ⇒ seccomp required. |
| Granted interpreter / multitool runs a *different* binary | **Closed** for the exec boundary (Findings 1, 3, 4): it cannot spawn outside the set. Its in-process logic stays governed by fs/net, not exec. |
| `posix_spawn` / shebang interpreter | **Governed** — `process-exec*` covers `posix_spawn`; a shebang requires its interpreter granted too (Finding 5). |
| Basename collision in an untrusted dir; `$PATH` shadow | **Closed** — bare names resolve through a *fixed trusted* PATH only (D2). |
| Allow-listed dynamic binary fails to load | **Not a bypass** — it loads and runs; the exec allow-list does not gate the kernel dyld path (Finding 5). |
| No `sandbox-exec` (incapable host) | **Fails closed** — `command_prefix` returns `Err` rather than an unconfined prefix; honest `SandboxKind::None` upstream. |

## Consequences

**Positive**
- macOS gets **kernel-grade `exec` confinement that covers the interior with a
  single mechanism** — stronger than the Linux Tier-1 increment, which needs
  Landlock + seccomp and still surrenders the interpreter case.
- `#57` is closed for macOS honestly: a restricted `exec` is either kernel-confined
  or (no `sandbox-exec`) refused — never silently ambient.
- One profile, one wrapper, same `SandboxKind::Seatbelt`, same call site; the
  `meet` law is undisturbed (the exec rules only ever deny more).

**Negative / risks**
- **`TRUSTED_EXEC_DIRS` is FHS-on-macOS-tuned.** A grant naming a binary outside
  `/usr/bin`,`/bin`,`/usr/sbin`,`/sbin` by bare name won't resolve and is dropped
  (deny-of-function, not a safety failure); grant the absolute path for tools in
  `/opt/homebrew`, `/usr/local`, etc.
- **`sandbox-exec(1)` is Apple-deprecated-but-present**; the backend already
  depends on it for fs/net, so `exec` rides the same wrapper and the same risk.
- **`exec → Kernel` is a *boundary* claim, not interior-identity for interpreters**
  — a granted interpreter's own logic is governed by fs/net, not exec. Reviewers
  must read the axis report at grain (D4).

## Options considered and rejected

- **Mirror ADR 0011 exactly — report `exec → Interceptor` and add a backstop** —
  rejected: Findings 3–4 show macOS has no trampoline to backstop, so reporting
  `Interceptor` would *under-claim* a real kernel boundary, and adding a second
  mechanism would be dead weight. The honest report at this grain is `Kernel`.
- **Declare a granted interpreter `exec ≡ All` (ADR 0011 D6) on macOS too** —
  rejected: the macOS exec boundary holds for interpreters (the trampoline is
  closed), so the downgrade would be dishonest in the *pessimistic* direction. The
  interpreter's interior is disclosed via the fs/net axes instead.
- **Resolve bare names through the ambient `$PATH`** — rejected (D2): a planted
  binary earlier on `$PATH` would widen the kernel allow-list. Fixed trusted PATH
  only.
- **`(allow process-exec* (subpath <dir>))` on a directory** — rejected: a subpath
  grant would make every binary beneath an allow-listed directory runnable,
  defeating the axis (the macOS analog of ADR 0011's "loader/program *files*
  only"). Literal file paths only.

## Follow-ups

- **#57** — exec frontier: closed for macOS here; the Linux Tier-1 increment
  (Landlock + seccomp, ADR 0011) and Tier-2 identity (ADR 0009 D2) remain.
- **#30** — the `exec` report arm now distinguishes `Seatbelt → Kernel` from the
  held Landlock case.
- Bare-name resolution beyond the system dirs (Homebrew/`/usr/local`) if a future
  consumer needs it — currently absolute-path grants cover it.
