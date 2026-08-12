# POSIX Projection — Threat Model (hostile child)

Status: **Design.** Companion to
[posix-authority-model.md](posix-authority-model.md) and
[ADR 0026](../adr/0026-posix-authority-projection.md). This document states the
adversary the projection must survive and maps each capability to the model's
answer. It does not describe an implementation.

## Adversary

**The executed program is hostile and fully capable.** It is not a cooperating
tool that happens to be confined; it is an attacker who has already achieved code
execution inside the fence and wants authority the grant did not delegate. It may:

- issue **direct syscalls**, avoiding libc entirely (so **`LD_PRELOAD` /
  libc interposition is NOT the boundary** — it is at most a compatibility
  convenience *above* the boundary);
- be a **static binary**, an interpreter, or a shell that re-execs;
- **spawn descendants** and exec unexpected binaries;
- use **`io_uring`** to perform I/O without the classic syscall entry;
- use **AF_UNIX sockets** and pass descriptors via **`SCM_RIGHTS`**;
- **abuse inherited descriptors** the parent forgot to close;
- exploit **`/proc`** (`/proc/self/fd`, `/proc/PID/*`), **symlinks**,
  **hardlinks**, **bind mounts**, and **rename races** (TOCTOU) against pathname
  resolution;
- attempt **namespace escapes**, **`ioctl`** on any reachable fd, and invocation
  of **helpers/deputies** (setuid binaries, mach/XPC services) that hold
  authority the child does not;
- manipulate **environment variables**, the **dynamic loader**, and
  **shell/executable substitution** to redirect exec.

This is the standard "confined but adversarial descendant" model already
exercised by the repo's hostile-child tests (`agent-bridle-tool-shell/tests/real_spawn.rs`,
`seatbelt_net_evidence.rs`, `aclaunch/tests/kernel_proofs.rs`).

## Trust boundary

Enforcement lives at the **kernel fence** (Landlock/seccomp, Seatbelt SBPL,
AppContainer DACL+capability-SID) and at the **admit→apply content binding**
(`AdmittedFence`). It does **not** live in any userspace shim inside the child's
address space. Anything the child can rewrite (its libc, its loader, its env, its
memory) is *inside* the boundary and therefore untrusted.

## Threat → model answer

| # | Hostile action | Model / mechanism answer | Status |
|---|---|---|---|
| 1 | Direct syscall, no libc | Kernel fence mediates regardless of libc (Landlock/seccomp/SBPL/DACL) | Faithful (fs); Interceptor (exec); see matrix |
| 2 | Ambient pathname `open()` against host root | Namespace non-amplification: resolution bounded by `effective`; projected namespace omits ungranted objects | Model-proven; real-path needs #319 |
| 3 | Inherit an ambient fd across `exec` | **#319** — `close_range` on spawn (not yet built); today CLOEXEC-convention only | **Open residual** |
| 4 | `dup`/`fcntl` an existing fd | Descriptor non-amplification: rights ⊆ source | Faithful (model) |
| 5 | Reopen via `/proc/self/fd/N` with wider mode | Reopen re-mediated as `Lookup` against `effective`, not trusted as fd-derived | Design; needs `/proc` restriction |
| 6 | `O_PATH` fd upgraded to full access | Treated as `Lookup`, re-mediated | Design |
| 7 | `openat(dirfd,"..")` / `AT_EMPTY_PATH` escape | Require `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` | Design (Linux) |
| 8 | Symlink / hardlink / bind-mount / rename TOCTOU | Object-stability: non-canonical root ⇒ `Unknown ⇒ refuse` (E1, `sandbox.rs:1139`) | Faithful (fs read/write roots) |
| 9 | `io_uring` async I/O bypass | seccomp denies `io_uring_setup/enter/register` (`sandbox.rs:1462`, E3) | Faithful under `DenyDirect`; `Unknown` under default `LandlockOnly` |
| 10 | AF_UNIX + `SCM_RIGHTS` descriptor passing | Modeled as `Delegate` on `IPCChannel`; received rights ⊆ sender's | Design; abstract-ns unix socket = bounded residual (`config.rs:159`) |
| 11 | Spawn a descendant to escalate | Descendant attenuation: child ⊑ parent (kernel fence inherited by the child) | Faithful (model + real: `real_spawn.rs` grandchild tests) |
| 12 | `ioctl` on a reachable device fd | `Device` ops resolve to `Unknown ⇒ refuse`; no grantable device object | By-design refusal |
| 13 | Invoke a deputy (mach/XPC, setuid helper) | Deputy channels reported `Unknown`; E4 mach-lookup floor closes the *demonstrated* nsurlsessiond path only | **Bounded residual (E4)** |
| 14 | `mmap(PROT_EXEC)` after reading a file | ld.so trampoline; exec is honestly `Interceptor`, never `Kernel` (`sandbox.rs:1052`) | Reported, not closed |
| 15 | Env / loader manipulation (`LD_PRELOAD`, `BASH_ENV`) | `env_clear` on spawn (`spawn.rs:650`) + loader denylist (`config.rs:487`) | Faithful (parent-side) |
| 16 | Metadata harvest (`stat`, topology) while content denied | `Inspect` axis reported `Unknown` on all backends; not folded into `fs_read` (ASM-MACOS-METADATA) | Reported residual |

## Why direct-syscall bypass does not defeat the architecture

The boundary is the kernel fence, not a syscall filter that must enumerate every
entry point. A direct `write(2)` to an out-of-scope path is denied by the same
Landlock ruleset that denies a libc `fopen`; the child cannot syscall its way
around a filesystem ruleset that governs its own address space. The one place a
syscall *class* matters is egress (io_uring, raw sockets), which is why seccomp
composes under Landlock (E3) — and where that composition is not installed
(default `LandlockOnly`), the net axis is honestly reported `Advisory`/`Unknown`,
never `Kernel`.

## Residuals carried into the projection (do not re-discover as new)

- **#319** — ambient descriptors not closed on spawn (threat #3). Slice-1 target.
- **E1** — symlinked/non-canonical root ⇒ `Unknown` (threat #8). Enforced.
- **E3** — io_uring / `net:none` under default `LandlockOnly` (threat #9).
- **E4** — macOS mach-lookup/XPC ambient deputy (threat #13). Bounded.
- **ld.so trampoline** — exec is `Interceptor`, not `Kernel` (threat #14).
- **Inspect/metadata** — no backend confines it (threat #16).
