# Native Agent Brief — macOS POSIX Projection Probes

**Audience:** a native-macOS Bridle agent with real Apple hardware (Apple
Silicon preferred; the existing Seatbelt evidence was gathered there —
[`docs/reviews/2026-07-04-seatbelt-live-owner-mac.md`](../reviews/2026-07-04-seatbelt-live-owner-mac.md)).

**Prime directive — do not guess.** Every question below is answered by *running
a probe on real hardware and reading the result*, never by recalling how macOS
"should" behave. If you cannot run a probe, the answer is **`Unknown`**, not your
best inference. Apple's sandbox behavior is version-specific and undocumented in
places; a remembered fact is not evidence.

**Honesty rule — distinguish denial from inability.** Every probe must include a
**positive control**: a case that MUST succeed if the mechanism is working, run
alongside the case that must be denied. A `connect` that fails because nothing is
listening is not a denial. Model the existing evidence tests
(`agent-bridle-tool-shell/tests/seatbelt_net_evidence.rs` uses parent-side
listeners + positive controls precisely for this reason).

**Grounding (read first, do not duplicate):**
[posix-authority-model.md](../design/posix-authority-model.md),
[posix-authority-matrix.md](../design/posix-authority-matrix.md),
[posix-threat-model.md](../design/posix-threat-model.md),
[ADR 0026](../adr/0026-posix-authority-projection.md).

**Existing macOS substrate (the starting points — cite, do not re-derive):**
- Seatbelt projection: `agent-bridle-core/src/sandbox.rs` (`seatbelt_impl`, cfg
  `macos-seatbelt`). SBPL profiles run via `/usr/bin/sandbox-exec`; `apply()` is
  a no-op, the boundary is entirely `command_prefix`.
- **ASM-MACOS-METADATA** (`formal/assurance/assumptions.md`): the SBPL emits
  `(allow file-read-metadata)` — `stat`/existence/size/topology stay ambient even
  when content read is denied. Registered residual: metadata is orthogonal to
  content `fs_read` and MUST NOT be modeled as content authority.
- **E4**: mach-lookup / XPC ambient network **deputy** under `net:none`. The E4
  Seatbelt Mach-lookup floor closes only the *demonstrated*
  background-URLSession → `com.apple.nsurlsessiond` path — defense-in-depth, NOT
  deputy-complete (claim `MACOS-E4-NSURLSESSIOND-DEFENSE`, `manifest.toml`).
- Seatbelt `resolved_authority` is `ResolvedAuthority::from_delegated(effective)`
  — a **`verbatim`** placeholder (not a faithful ruleset-grain projection); I15
  stays Partial for macOS.
- exec: a granted `/bin/sh` forces `/bin/bash` into the allowlist (Apple `sh`
  re-execs bash; agent-bridle#318). Bare names resolve only against a fixed
  trusted list, never `$PATH`.

---

## 1. Metadata / inspect channel (settles the `inspect` class on macOS)

The matrix carries `inspect` as `Unknown ⇒ refuse`. Probe whether macOS can do
better than the current ambient-metadata residual.

1. With an SBPL profile that denies `file-read*` on a target, probe whether
   `stat(2)`, `access(2)`, `lstat`, `getattrlist`, and directory enumeration
   (`readdir`) on that target still succeed. Positive control: a granted path
   whose metadata MUST be readable.
2. Probe whether removing `(allow file-read-metadata)` from the generated profile
   denies `stat` — and what breaks (does symlink-ancestor traversal to an
   in-scope file fail, as the code comment at `sandbox.rs:1971` claims?).
3. Determine the *minimum* metadata that must stay ambient for a normal tool
   (e.g. `git status`, `cargo build`) to function. Report the exact SBPL
   operations involved. **Do not assume — measure with a real toolchain.**
4. Verdict: is metadata confinement `Unsupported` on macOS (ambient is
   irreducible), or `Conservative` (some subset is deniable)?

## 2. Descriptor-as-capability

The model (§4) treats a descriptor as an authority-bounded capability. Probe how
close macOS gets.

1. Probe `SCM_RIGHTS` over AF_UNIX under Seatbelt: can a confined child receive a
   descriptor for an out-of-scope object? Does the SBPL fence apply to the
   *received* fd or only to path-based opens?
2. Probe `/dev/fd/N` reopen and `fcntl(F_DUPFD)`: can a child widen access mode
   by reopening an fd it already holds? Positive control: reopen at the same mode
   must succeed.
3. Probe whether macOS offers any Capsicum-like descriptor-only mode
   (it does not have `cap_enter`, but confirm — do not assume). Report what
   descriptor-relative primitive (`openat` semantics under Seatbelt) exists.

## 3. Mach / XPC deputy surface (E4 — bounds the deputy residual)

E4 is explicitly NOT deputy-complete. Enumerate the residual.

1. Under `net:none`, enumerate child-drivable ambient IPC deputies **beyond**
   `nsurlsessiond` that can perform network egress on the child's behalf. Candidate
   probes: `com.apple.nsurlstoraged`, `com.apple.CFNetwork`, XPC services reachable
   via `xpc_connection_create_mach_service`, `NSXPCConnection`. For each: can a
   confined child reach it, and can it cause off-box traffic? Positive control: a
   direct `connect` that MUST be denied.
2. Probe the loopback and loopback-proxy shapes (ADR 0015/0016) for the same
   deputy question: does routing egress through the loopback proxy leave any
   mach/XPC deputy path open?
3. Report each deputy as a distinct residual row; do NOT collapse them into "E4
   handled."

## 4. Faithful `resolved_authority` (closes the I15-Partial gap)

The current projection is `verbatim` (re-asserts the caveats). A faithful
ruleset-grain projection is needed.

1. Probe SBPL expressiveness for a **non-empty exec allowlist**: can
   `(allow process-exec* (literal ...))` faithfully bound exec to a resolved set,
   including the sh→bash launcher case (#318)? What is the residual?
2. Probe remote-host `net`: SBPL cannot express a general remote host
   (`sandbox.rs:1994`, ADR 0015). Confirm on hardware and characterize exactly
   what network predicates SBPL *can* express (`(allow network* (remote ip ...))`
   forms). **Do not invent SBPL syntax — if unsure, phrase the exact profile you
   tested and its observed effect.**
3. Determine what a faithful `ResolvedAuthority` would report per axis (Bounded /
   Unbounded / Unknown) to replace `from_delegated`.

## 5. Object identity / canonicalization (E1 analog)

1. Probe symlink, firmlink, and `/private` → `/tmp` canonicalization: does the
   SBPL `(subpath ...)` match survive Apple's firmlink layer? Positive control: an
   in-scope subpath that MUST match.
2. Probe APFS clones and hardlinks: can a child reach an out-of-scope object via a
   clone/hardlink whose canonical path is in-scope?
3. Verdict: does the E1 object-stability guarantee (non-canonical root ⇒
   `Unknown`) hold on APFS?

## 6. Descriptor inheritance on spawn (#319 analog)

1. Probe whether `posix_spawn` / `NSTask` closes ambient descriptors, or whether
   the CLOEXEC convention is the only barrier (as on Linux, `spawn.rs:342`).
2. Probe for a `close_range(2)` equivalent on macOS (does it exist? what version?).
   Report the exact primitive available for closing ambient fds on spawn.

## 7. `ioctl` / device and cross-process signal

1. Probe whether Seatbelt confines `ioctl` on device fds. The model refuses
   `Device` ops; confirm macOS cannot faithfully bound them.
2. Probe cross-process signalling (`kill` to another process) and `/proc`-analog
   process discovery (`sysctl`/`proc_listpids`): does Seatbelt confine them? The
   model treats cross-process `signal` as `Unsupported ⇒ refuse`; confirm.

---

## Reporting format

For each probe, report a row:

```
primitive | class ∈ {Faithful, Conservative, Unsupported, Unknown}
          | positive-control evidence (what succeeded that proves the deny is a deny)
          | SBPL/profile fragment actually tested
          | residual (if any)
```

These rows feed the macOS columns of
[`formal/assurance/refinement_matrix.toml`](../../formal/assurance/refinement_matrix.toml)
and any new `ASM-POSIX-*` premises. **A probe you could not run is reported as
`Unknown`, never as a remembered class.** SKIP is not PASS.
