# Native Agent Brief — Windows POSIX Projection Probes

**Audience:** a native-Windows Bridle agent with real Windows hardware (the
AppContainer proofs run under `BRIDLE_REQUIRE_APPCONTAINER`; net proofs need
`BRIDLE_REQUIRE_ELEVATED`).

**Prime directive — do not guess.** Every question is answered by *running a
probe and reading the result*, never by recalling Win32 semantics. Windows access
control (DACLs, capability SIDs, LPAC, WDAC) is intricate and version-specific; a
remembered fact is not evidence. If you cannot run a probe, the answer is
**`Unknown`**, not an inference.

**Honesty rule — distinguish denial from inability.** Every probe includes a
**positive control** that MUST succeed if the mechanism works, run alongside the
case that must be denied. A failed `connect` because nothing listens is not a
denial. Model the existing tests: `agent-bridle-aclaunch/tests/kernel_proofs.rs`
and `net_proofs.rs` (with `ab-netprobe.rs`) already pair denials with controls.

**Grounding (read first, do not duplicate):**
[posix-authority-model.md](../design/posix-authority-model.md),
[posix-authority-matrix.md](../design/posix-authority-matrix.md),
[posix-threat-model.md](../design/posix-threat-model.md),
[ADR 0026](../adr/0026-posix-authority-projection.md).

**Existing Windows substrate (starting points — cite, do not re-derive):**
- AppContainer projection: `agent-bridle-core/src/sandbox.rs` (`appcontainer_impl`,
  cfg `windows-appcontainer`) + launcher `agent-bridle-aclaunch/src/main.rs`.
  Confinement is applied by the launcher (`CreateAppContainerProfile`,
  `SECURITY_CAPABILITIES`, capability SIDs, DACLs), not in-process.
- **E2**: write grants use `FILE_GENERIC_READ_WRITE` (`aclaunch/src/main.rs:476`) —
  a **write grant confers read**. The faithful projection reveals this:
  `resolved.fs_read = delegated.fs_read ∪ delegated.fs_write`, so admission
  refuses when `fs_write ⊄ fs_read` (claim `WIN-E2-WRITE-READ`, native test
  `kernel_proofs.rs::fs_write_grant_confers_read_e2`). Status: landed on main,
  **not RC-certified** (`ASM-WIN-DACL`).
- Net: capability SIDs (`WinCapabilityInternetClient*`) added only with
  `--net-allow`, empty otherwise (deny-by-default egress). Loopback via
  `NetworkIsolationSetAppContainerConfig` (`--loopback-exemption`). Remote-host
  allowlist ⇒ `Unknown`.
- Child-process block: `PROCESS_CREATION_CHILD_PROCESS_RESTRICTED`
  (`--no-child-process`).
- exec: a non-empty exec allowlist is **inexpressible** on AppContainer ⇒
  `Unknown` (only deny-all exec is `Kernel`). WDAC exec allowlist is an **accepted
  non-goal** (ADR 0009 D6).
- **Job Objects: not used** (grep finds none); ADR 0009 D4 re-scoped #51 *away
  from* job objects toward AppContainer — they are "resource limits, not a
  capability boundary."
- Env: `CreateProcessW` uses `lpEnvironment = null` (inherits launcher env) — the
  env boundary lives in the **parent** (`spawn.rs` `env_clear`), not the launcher.
  #323 tests: `windows_env_isolation.rs`, `windows_appcontainer_env.rs`.
- Maturity: ADR 0009 D6 declares the Tier-1 Windows backend "complete" for the
  kernel-proven axes; LPAC / named-object isolation and registry / named-pipe
  isolation are accepted non-goals.

---

## 1. Descriptor-as-capability (Windows HANDLEs vs POSIX fds)

The model (§4) treats a descriptor as an authority-bounded capability. Windows
HANDLEs are the analog.

1. Probe HANDLE inheritance under `CreateProcessW` with `bInheritHandles=TRUE`
   (the launcher uses this, `main.rs:614`): which handles cross into the
   AppContainer child, and can the child use an inherited handle to reach an
   out-of-scope object? Positive control: a granted handle that MUST work.
2. Probe `DuplicateHandle`: can a child duplicate a handle to widen access rights
   beyond the source handle's granted access? Report the access-mask semantics.
3. Probe whether AppContainer mediates handle-*derived* access (a handle opened
   before entering the container, or passed in) versus path-based opens. Is there
   a Windows analog of "descriptor-relative, no ambient namespace"?

## 2. E2 — write-implies-read (the headline; feeds RC-SHA re-certification)

1. Probe whether a **write-only ACE** is expressible: can a DACL grant
   `FILE_WRITE_DATA` / `FILE_APPEND_DATA` **without** `FILE_READ_DATA` to the
   AppContainer SID, such that the child can write but not read the same file?
   Positive control: a read that MUST succeed on a read-granted path, and a write
   that MUST succeed on a write-granted path.
2. If a write-only ACE *is* expressible, report the exact access-mask combination —
   this would let the projection drop the E2 `fs_read = fs_read ∪ fs_write`
   widening. If it is **not** (write implies read at the AppContainer-SID grain),
   confirm E2 is irreducible and the union projection is correct.
3. Re-run `kernel_proofs.rs::fs_write_grant_confers_read_e2` under the **frozen RC
   SHA** (not an ancestor SHA) to move `ASM-WIN-DACL` from `partial` to
   RC-certified.

## 3. Metadata / inspect

1. Probe whether AppContainer/DACL can deny **metadata** (`GetFileAttributes`,
   `FindFirstFile`, directory enumeration via `NtQueryDirectoryFile`) while
   denying content — or whether metadata is ambient as on macOS. Positive control:
   metadata on a granted path that MUST be readable.
2. Verdict: is the `inspect` class `Unsupported` (metadata ambient) or
   `Conservative` (deniable) on Windows?

## 4. Object identity / canonicalization (E1 analog)

1. Probe NTFS junctions, symbolic links, hardlinks, `\\?\` paths, and 8.3 short
   names: can a child reach an out-of-scope object via a link/short-name whose
   canonical path is in-scope? Positive control: an in-scope path that MUST resolve.
2. Probe how the launcher's `grant_path_access` DACL interacts with these — does
   the ACE follow the canonical object or the name?
3. Verdict: does the E1 object-stability guarantee hold on NTFS?

## 5. Exec allowlist (currently `Unknown`)

1. Probe whether **WDAC** (or AppLocker, or any mechanism composable with
   AppContainer) can express a non-empty exec allowlist — execute only a resolved
   set of images — and at what cost/privilege. Positive control: a granted binary
   that MUST run.
2. If nothing can express it, confirm exec stays `Unknown` for non-empty
   allowlists and only deny-all-child-process (`--no-child-process`) is `Kernel`.

## 6. Net

1. Probe remote-host allowlist expressibility: AppContainer capability SIDs are
   all-or-nothing internet access. Confirm a per-host allowlist is inexpressible
   at the SID grain (currently `Unknown`), and probe whether a loopback-fenced
   egress proxy (as on macOS, ADR 0016) is viable — is loopback the *only*
   reachable egress once InternetClient SIDs are withheld?
2. Probe `--loopback-exemption` behavior: does
   `NetworkIsolationSetAppContainerConfig` fence egress to loopback only, and does
   off-box stay denied? Positive control (needs elevation): loopback MUST work,
   off-box MUST fail.

## 7. Cross-process signal / process control

Windows has no POSIX signals; probe the analogous authority.

1. Probe `OpenProcess` / `TerminateProcess` / `DebugActiveProcess` from inside the
   AppContainer against a process outside it: is cross-process control confined?
2. The model treats cross-process `signal` as `Unsupported ⇒ refuse`; confirm
   AppContainer does not grant it, and report whether the child can enumerate
   other processes (`NtQuerySystemInformation`, `CreateToolhelp32Snapshot`).

## 8. `ioctl` / device analog

1. Probe `DeviceIoControl` from inside the AppContainer: can the child reach
   device objects, and is the access confined by the container? The model refuses
   `Device` ops; confirm Windows cannot faithfully bound them at the AppContainer
   grain.

## 9. IPC / descriptor passing (SCM_RIGHTS analog)

1. Probe **named pipes** and **ALPC**: can a confined child connect to a named
   pipe or ALPC port outside its grant? Is there a handle-passing analog of
   `SCM_RIGHTS` (e.g. `DuplicateHandle` into another process), and is it mediated
   by AppContainer?
2. Report whether IPC delegation is `Unsupported ⇒ refuse` or has a faithful
   projection.

---

## Reporting format

For each probe, report a row:

```
primitive | class ∈ {Faithful, Conservative, Unsupported, Unknown}
          | positive-control evidence (what succeeded that proves the deny is a deny)
          | exact mechanism tested (DACL mask / SID / API + flags)
          | residual (if any)
```

These rows feed the Windows columns of
[`formal/assurance/refinement_matrix.toml`](../../formal/assurance/refinement_matrix.toml),
the RC-SHA re-certification of `ASM-WIN-DACL`, and any new `ASM-POSIX-*`
premises. **A probe you could not run is reported as `Unknown`, never as a
remembered class.** SKIP is not PASS. Do not invent Win32 API details — if
unsure, report the exact call and flags you tested and the observed result.
