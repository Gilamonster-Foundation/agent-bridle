# POSIX Authority Matrix

Status: **Design.** The prose view of the per-operation authority audit. The
machine-checked rows live in
[`formal/assurance/refinement_matrix.toml`](../../formal/assurance/refinement_matrix.toml)
(POSIX section) and the claims in
[`manifest.toml`](../../formal/assurance/manifest.toml). This table answers, for
every projected POSIX operation: **what authority it requires, which Bridle axis
carries it, and whether the four axes are sufficient / insufficient / uncertain.**

The rule this table enforces (acceptance gate): **no operation may fall into a
generic "syscall allowed" bucket.** Every row maps to an explicit authority or to
an explicit `Unknown ⇒ refuse`.

## Legend

- **Axis**: `fs_read` / `fs_write` / `exec` / `net` (existing `Caveats` axes), or
  a named new class (`inspect`, `delegate`, `signal`) that the model carries but
  does **not** yet fold into an axis.
- **Sufficiency**: `sufficient` (an existing axis carries it faithfully),
  `insufficient` (needs a distinct class; today resolves to `Unknown ⇒ refuse`),
  `uncertain` (needs a native probe — see the platform briefs).

| POSIX operation | Object | Authority required | Bridle axis | Sufficiency | Rationale |
|---|---|---|---|---|---|
| `open`/`openat` (read) | File | read content of a stable object | `fs_read` | sufficient | Landlock `ReadFile`, SBPL `file-read*`, DACL read |
| `open`/`openat` (write) | File | write content | `fs_write` | sufficient | Landlock `from_write`, SBPL `file-write*`, DACL write (E2 on Windows: write⇒read) |
| `stat`/`access`/`readdir` topology | File/Dir | existence, size, owner, times, layout | **`inspect`** | **insufficient** | Content ≠ metadata; no backend confines metadata (ASM-MACOS-METADATA). Reported `Unknown`, never folded into `fs_read` |
| `Lookup` (path traversal) | Directory | resolve a name to an object | (resolution, not authority) | sufficient | Namespace non-amplification: bounded by `effective`; object-stability E1 |
| `creat`/`mkdir` | File/Dir | create under a writable root | `fs_write` | sufficient | write on the parent directory root |
| `unlink`/`rmdir` | File/Dir | delete under a writable root | `fs_write` | sufficient | write on the parent |
| `rename` | Dir | = create+delete | `fs_write` | sufficient | no new authority; rename TOCTOU handled by object-stability |
| `execve` | Executable | execute a resolved image | `exec` | sufficient (strength `Interceptor`) | Landlock `Execute` kernel-denies direct execve of ungranted images; ld.so mmap trampoline keeps strength at `Interceptor` not `Kernel` |
| `mmap(PROT_EXEC)` | File | execute mapped bytes | `exec` | **uncertain** | Landlock has no mmap hook; the trampoline residual |
| `connect` (remote) | SocketEndpoint | egress to (host,port) | `net` | uncertain (Linux advisory) | Kernel on Seatbelt/AppContainer; Linux = Landlock port-deny + seccomp (E3), remote-host = proxy (advisory) |
| `connect` (loopback) | SocketEndpoint | loopback IPC | `net` | sufficient | but a single-address grant is widened to the whole loopback interface (reported sub-`Kernel`) |
| `bind`/`listen`/`accept` | SocketEndpoint | serve | `net` | uncertain | same projection as connect; ingress semantics need a native probe |
| `socket(AF_UNIX)` + `sendmsg(SCM_RIGHTS)` | IPCChannel | **delegate a descriptor** | **`delegate`** | **insufficient** | not egress, not fs; descriptor delegation is its own class. Abstract-namespace unix socket = bounded residual (`config.rs:159`) |
| `pipe`/`socketpair` inheritance | IPCChannel | inherited channel | `delegate` | insufficient | modeled as `Delegate`; rights ⊆ creator |
| `kill`/`sigqueue` (own group) | Process | signal own process group | (self-authority) | sufficient | process-group kill exists (`spawn.rs:666`) |
| `kill` (other process) | Process | signal across the process boundary | **`signal`** | **insufficient** | cross-process signalling unmodeled → `Unknown ⇒ refuse` |
| `/proc/PID/*` discovery | Process | enumerate/inspect other processes | **`inspect`**/`signal` | insufficient | reported `Unknown`; pidfd for stable process identity |
| `ptrace` | Process | debug/control another process | **`signal`** | insufficient | `Unknown ⇒ refuse`; never a grantable object |
| `ioctl` | Device | driver-defined multiplexed authority | **none (refuse)** | **insufficient by design** | untyped multiplexer; `Device` ops resolve `Unknown ⇒ refuse` |
| `io_uring_setup` | (bypass) | async syscall submission | (denied) | sufficient (deny) | seccomp deny under `DenyDirect` (E3); `Unknown` under default `LandlockOnly` |
| env / loader vars | (process state) | influence exec/loading | (state, not object) | sufficient | `env_clear` + loader denylist (`config.rs:487`) |

## Summary

- **Sufficient (existing four axes carry it faithfully):** file read/write,
  directory create/delete/rename, execve (at `Interceptor` strength), loopback
  net, own-group signal, env/loader state, io_uring deny.
- **Insufficient (needs a distinct class; today `Unknown ⇒ refuse`):** metadata
  `inspect`, descriptor `delegate` (SCM_RIGHTS/IPC), cross-process `signal`,
  `ioctl`/device.
- **Uncertain (needs a native probe — see briefs):** remote `net`
  bind/listen/accept semantics, `mmap(PROT_EXEC)`.

The four axes are **not** expanded. The insufficient classes are carried as named
`Unknown` rows so they are *reported and refused*, never silently folded into an
existing axis — which is the honest alternative to inventing axes we cannot yet
enforce.
