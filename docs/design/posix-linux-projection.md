# POSIX Projection — Linux Mechanism Mapping

Status: **Design.** How the abstract machine
([posix-authority-model.md](posix-authority-model.md)) projects onto Linux
mechanisms. The Linux coordinator owns the *abstract* architecture; this document
is the honest Linux feasibility view. macOS and Windows are handed to native
agents ([posix-cross-platform-questions.md](posix-cross-platform-questions.md),
briefs under [`docs/briefs/`](../briefs/)).

Classification per the existing vocabulary (`refinement_matrix.toml` `class`):

- **Faithful** — the mechanism enforces exactly the abstract authority.
- **Conservative** — enforces a subset (refuses more than strictly required) but
  never widens.
- **Unsupported** — the platform cannot express it; the model **refuses** rather
  than widen.
- **Unknown** — a known bypass or unproven bound exists; `Unknown ⇒ refuse`.

No single mechanism enforces everything. The projection is a *composition*.

## Mechanism inventory (what exists in-repo)

| Mechanism | Where | Enforces |
|---|---|---|
| Landlock ABI-v4 | `sandbox.rs:928` (`landlock_impl`) | fs read/write beneath canonical roots; TCP port deny; exec via `Execute` |
| seccomp (`seccompiler`) | `sandbox.rs:1433` | socket-family deny (AF_INET/6/PACKET) + `io_uring_*` deny, under `DenyDirect` |
| `openat2(RESOLVE_*)` | `agent-bridle-fdguard/src/beneath.rs` (`open_beneath_*`, #351) | beneath-root, no-symlink lookup |
| pidfd | (design) | stable process identity (pid-reuse-safe) |
| mount/user/net namespaces | `agent-bridle-jaild` (unwired) | rootfs jail, netns egress fence |
| egress proxy | `net_proxy.rs` | loopback-fenced HTTP CONNECT — **Seatbelt/AppContainer only**, refused on Linux (`sandbox.rs:478`) |

## Per-operation Linux classification

| Abstract op | Linux mechanism | Class | Note |
|---|---|---|---|
| File read (beneath canonical root) | Landlock `ReadFile\|ReadDir` | **Faithful** | strength `Kernel` (`report.rs:226`) |
| File write (beneath canonical root) | Landlock `from_write` | **Faithful** | `Kernel` |
| Directory create/delete/rename | Landlock (write on parent) | **Faithful** | rename covered by `Refer` (ABI≥3, `sandbox.rs:972`) |
| Lookup with symlink/non-canonical root | object-stability check | **Unknown** | E1: non-canonical root ⇒ refuse (`sandbox.rs:1139`) |
| Lookup `openat("..")` / `/proc/self/fd` reopen | `openat2(RESOLVE_BENEATH\|NO_SYMLINKS)` | **Conservative** | wired (#351): `open_scoped_*` re-mediates the parent-side redirect opens against `effective` in one kernel-bounded step (fdguard `open_beneath_*`); in-root symlinks refused too |
| Execute (resolved image) | Landlock `Execute` | **Conservative** | direct execve kernel-denied; strength `Interceptor` not `Kernel` — ld.so mmap trampoline (`sandbox.rs:1052`) |
| `mmap(PROT_EXEC)` | — | **Unknown** | Landlock has no mmap hook |
| Net: `net:none` under `DenyDirect` | Landlock TCP-deny + seccomp socket/io_uring deny | **Faithful** | `Kernel` (`report.rs:321`) |
| Net: `net:none` under default `LandlockOnly` | Landlock TCP-deny only | **Unknown** | UDP/DNS/raw/io_uring open (E3) → `Advisory` |
| Net: remote-host allowlist | (netns+veth proxy unbuilt) | **Unknown** | proxy refused on Linux (`sandbox.rs:478`); reported `Advisory` |
| Net: loopback | Landlock port rules | **Conservative** | single-address grant widened to whole interface |
| `io_uring` | seccomp deny (`DenyDirect`) | **Faithful (deny)** | E3; `Unknown` under `LandlockOnly` |
| AF_UNIX / `SCM_RIGHTS` delegate | — | **Unknown** | not modeled; abstract-ns unix socket residual (`config.rs:159`) |
| Cross-process signal / ptrace / `/proc` discovery | (pidfd design; unbuilt) | **Unsupported ⇒ refuse** | no confinement today |
| `ioctl` / device | — | **Unsupported ⇒ refuse** | untyped multiplexer |
| Metadata `inspect` | — | **Unknown** | Landlock does not confine `stat` |
| Descriptor inheritance across exec | `close_range(3,..)` pre-exec via `agent-bridle-fdguard` (#319) | **Faithful (Linux)** | ambient fds >= 3 closed at every confined-spawn site, stdio preserved, fail-closed; macOS/Windows still CLOEXEC-convention |
| Env / loader | `env_clear` + denylist | **Faithful** | `spawn.rs:650`, `config.rs:487` |

## Composition and kernel prerequisites

- **fs Kernel floor requires canonical, symlink-stable roots** (E1). A grant root
  that does not canonicalize is `Unknown`, not "best effort."
- **net Kernel floor requires `DenyDirect`** (Landlock TCP-deny *and* the seccomp
  socket/io_uring leg). Default `LandlockOnly` is honestly `Advisory` for
  `net:none`.
- **Landlock filesystem confinement is not a complete boundary while unprivileged
  user namespaces remain available** — the repo already refuses the trusted
  worker in that case (`spawn.rs:806`, sysctl probe `spawn.rs:873`). The POSIX
  projection inherits this precondition.
- **The first slice (#319)** needs only kernel primitives already present on a
  Linux 6.8 kernel (Landlock ABI v4): `close_range(2)` and `openat2(2)` with
  `RESOLVE_BENEATH` / `RESOLVE_NO_SYMLINKS`. No new daemon, no broker —
  consistent with ADR 0026's no-broker-in-slice-1 decision.

## What Linux cannot do (refuse, do not widen)

`ioctl`/device authority, cross-process signal/ptrace, and metadata `inspect`
have **no faithful Linux projection today**. The model refuses them
(`Unknown/Unsupported ⇒ refuse`) rather than grant them under a broad allowlist.
A future netns+veth egress fence would move remote-host `net` from `Unknown` to
`Faithful`; a pidfd-based process-authority projection would move cross-process
`signal` from `Unsupported` to at least `Conservative`. Both are post-slice-1.
