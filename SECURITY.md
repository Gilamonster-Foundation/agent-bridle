# Security Policy

`agent-bridle` is the capability-enforcement **leash** for agent tools: a tool can
act only through a `ToolContext` minted inside `Gate::authorize`, and receives the
*meet* of granted-and-required authority (least authority by construction). Because
it is a security boundary, correctness and privacy are enforced in CI.

## Reporting a vulnerability

Open a private security advisory on this repository (GitHub → Security → Report a
vulnerability), or contact the maintainers out-of-band. Please do **not** file
public issues for undisclosed vulnerabilities.

## Hardening the host for L3 confinement

On Linux, the `linux-landlock` backend kernel-confines a permitted program's
filesystem reads/writes and denies a **direct** `execve` of an un-granted tool
(ADR 0011). Two residual escapes are not closed by Landlock alone and have host
mitigations an operator should apply:

- **Bind-mount re-point** — `unshare(CLONE_NEWUSER|CLONE_NEWNS)` then
  `mount --bind` a payload over a read-allowed path. This requires **unprivileged
  user namespaces**; disable them on the host to close it:
  - `sysctl -w kernel.unprivileged_userns_clone=0` (Debian/Ubuntu), and/or
  - `sysctl -w user.max_user_namespaces=0`, and/or
  - on Ubuntu ≥ 24.04, `sysctl -w kernel.apparmor_restrict_unprivileged_userns=1`.

  Most hardened hosts already set one of these.
- **Loader/interpreter trampoline** — `ld.so` `mmap`-execs any *readable* ELF, and
  a granted interpreter (`sh`, `python`, …) runs arbitrary in-process code.
  Landlock has no `mmap` hook, so this is **not** kernel-closed — which is exactly
  why `agent-bridle` honestly reports the `exec` axis as `interceptor`, never
  `kernel` (ADR 0011 D2/D7), and a strong principal **fails closed** on a
  restricted `exec` (ADR 0012). The sound close is the Tier-2 micro-VM /
  mount-namespace rootfs that physically excludes un-granted binaries (ADR 0009 /
  #57) — keep the read scope tight in the meantime. On **macOS**, Seatbelt
  `process-exec*` closes the axis at kernel grain by itself (no rootfs needed), so
  it reports `exec → kernel` (ADR 0014).
- **Reading `exec → kernel` (identity, not behavior).** Where the report does say
  `exec → kernel` (macOS Seatbelt today; a Linux minimal-rootfs later), it means
  **no un-granted program can run as a process** — *not* that a *granted* program,
  especially a granted **interpreter** (`sh`, `python`), is constrained in what it
  *does*. A granted interpreter's interior is governed only by the
  `fs_read`/`fs_write`/`net` axes; keep those tight, and grant interpreters only
  deliberately (they are the highest-authority `exec` choice — ADR 0012 D8).

> A future `linux-seccomp` backstop (ADR 0011 D4) could deny the mount/namespace
> syscall family in-process as defense-in-depth for the bind-mount case. It needs
> a hand-rolled, arch-guarded BPF filter — a single `seccompiler` `mismatch_action`
> cannot keep the wrong-arch guard distinct from the permissive default a denylist
> requires (the i386/x32 bypass) — so it must be authored and verified on a real
> Landlock+seccomp host; tracked under #57/#35. The host-sysctl mitigation above
> closes the same gap today, and a strong principal already fails closed regardless.

## Known security issues

### macOS Seatbelt: the Xcode.app git-toolchain exception trusts an admin-writable directory (agent-bridle#408/#409, #2630 rounds 3-4)

The `macos-seatbelt` `exec` axis (ADR 0014) admits `git`'s own re-exec of the
active developer toolchain only when the toolchain binary's full ancestor
chain is root-owned and unwritable (`ancestry_is_root_owned_and_unwritable`,
`sandbox.rs`). **One named exception, OPT-IN ONLY** (default OFF —
`SandboxPolicy::seatbelt_trust_admin_writable_xcode`, agent-bridle#409):
when the operator explicitly sets it, `/Applications` itself may be
admin-group-writable (`root:admin 0775`) without failing that walk, so the
stock Xcode.app toolchain — reached through it — can still be trusted. With
the flag unset (the default), `/Applications` under this bar fails closed
exactly like every other ancestor, and `git worktree add` on a stock Xcode
install stays denied. No other path gets this relaxation, at any ancestor
level, for any candidate, regardless of the flag.

**Risk (only when the operator has opted in):** on a Mac where `/Applications`
carries its default admin-group-writable mode, any process running as a
member of the `admin` group — ordinarily the logged-in user on a single-user
Mac, but any locally-compromised admin-group process too — can replace
`/Applications/Xcode.app` wholesale. Bridle's resolver would then admit the
replacement's `git` binary into a `git`-only exec grant, because it only
checks ownership/mode, never content or identity. This is a real narrowing
of the trust boundary below "root-owned toolchain" elsewhere in this policy:
it is an accepted, named, **opt-in** tradeoff, not an oversight and not the
default.

**Mitigation:** leave `seatbelt_trust_admin_writable_xcode` unset (the
default), or run `xcode-select -s /Library/Developer/CommandLineTools`.
CommandLineTools lives at a fully root-owned path end to end, so once it is
the active toolchain, the exception never applies to admit anything even
with the flag on — the resolver falls back to the unrelaxed ancestry bar
this policy uses everywhere else, and the resolved-authority exec axis never
carries the `seatbelt-admin-writable-xcode-toolchain` class.

**Detection:** a grant admitted only through this exception is named on the
resolved-authority exec axis as the class `seatbelt-admin-writable-xcode-toolchain`
(see ADR 0014's amendment) — never silently folded into the concrete grant.

### Windows AppContainer: the opt-in `NUL` device ACE widens a host device DACL (agent-bridle#408)

On affected Windows Server AppContainer policies, Git for Windows opens `NUL` during
startup even when all three standard handles are valid. The normal AppContainer
filesystem grant cannot authorize that host device. For the narrow native-Git
compatibility case tracked in [#408](https://github.com/Gilamonster-Foundation/agent-bridle/issues/408),
the launcher offers the explicit, default-off `--nul-device-ace` opt-in.
Without that option, it neither opens nor modifies `\\.\NUL`, and its
AppContainer-profile handling remains the existing baseline.

This is a documented security widening, not ordinary `fs_read`, `fs_write`, or
`exec` authority. When an operator explicitly enables it, the launcher modifies
the host `\\.\NUL` device DACL by adding one ACE for that launch's freshly created
AppContainer SID. The ACE grants only `FILE_GENERIC_READ | FILE_GENERIC_WRITE`;
it grants neither execute nor access to another AppContainer SID. The resolved
authority and enforcement disclosure name this closure
`appcontainer-nul-device-ace` so it cannot disappear into an empty report.

The caller must have `WRITE_DAC` on `\\.\NUL` (normally an elevated Windows token).
If that right is absent, the launcher refuses before spawning the child; it does
not retry without the requested grant. On every ordinary launcher exit it removes
exactly its own SID's ACE, never restores a saved whole DACL, because overlapping
launches must not delete or resurrect one another's grants. If the launcher
crashes before cleanup, or a revocation fails, its profile remains and a later
launcher invocation reaches the existing baseline failure:
`CreateAppContainerProfile` does not return a fresh SID for an existing profile,
so the child cannot start or reactivate that deterministic SID. External deletion
of the retained profile is outside this launcher lifecycle and can make a later
same-name creation possible while an unresolved ACE remains. The possible ACE is
therefore documented residual host state; it is not silently normalized into the
baseline.

This escape hatch must be retired when Git for Windows ships an upstream change
that avoids its unconditional `/dev/null` startup open when stdio is already
valid (the current call path is visible in
[Git for Windows `setup.c`](https://github.com/git-for-windows/git/blob/49d759b698127791a5f3f2759c69b983846711dd/setup.c#L2249-L2257)).
ADR 0009 records the boundary and retirement criterion.

#### Second opt-in: the MountPointManager ACE (`--mount-manager-ace`)

The `NUL` ACE alone does not make `git status` work. Git for Windows' `mingw_getcwd`
(`compat/mingw.c`, `v2.56.0.windows.4`) calls
`GetFinalPathNameByHandleW(VOLUME_NAME_DOS)`, which queries
`\Device\MountPointManager`. The AppContainer SID is denied there, so Git dies with
`Unable to read current working directory: Permission denied`. A separate,
default-off opt-in, `--mount-manager-ace` (policy field
`appcontainer_mount_manager_ace`), adds one explicit, non-inheriting ACE on that
device (opened as `\\?\GLOBALROOT\Device\MountPointManager`) for the launch's own
AppContainer SID. It grants `FILE_READ_ATTRIBUTES | SYNCHRONIZE` (`0x00100080`).
This is the measured minimum on the Windows Server CI runner: `0x00100000`, `0x80`,
`0x20000`, and `0x8` each fail alone. Enabling one opt-in never enables the other.
It follows the same lifecycle as the `NUL` ACE. That means it is per-launch SID
only, its add and remove are exact and serialized by its own global mutex, it fails
closed without `WRITE_DAC`, and it retains the profile, refusing SID reuse, when
cleanup fails. Its resolved-authority class is `appcontainer-mount-manager-ace`.
That class sits on the read axis only, and the report lists it as the widening
`appcontainer-mount-manager-ace`. When both opt-ins are on, the report lists both
widenings.

**Why this mask cannot change mount state.** The argument rests on documented
semantics, not on a live measurement. No mount-manager IOCTL was sent to test it.
The source is the MountPointManager IOCTL definitions in the driver-kit header
`mountmgr.h`, read from the mingw-w64 copy. Each IOCTL's `CTL_CODE` encodes the
access it requires:

- **State-changing IOCTLs need `FILE_READ_ACCESS | FILE_WRITE_ACCESS`:**
  `CREATE_POINT`, `DELETE_POINTS`, `DELETE_POINTS_DBONLY`, `NEXT_DRIVE_LETTER`,
  `AUTO_DL_ASSIGNMENTS`, `VOLUME_MOUNT_POINT_CREATED`/`DELETED`,
  `KEEP_LINKS_WHEN_OFFLINE`, `SCRUB_REGISTRY`, `SET_AUTO_MOUNT`, and
  `BOOT_DL_ASSIGNMENT`.
- **Notification and trace IOCTLs need `FILE_READ_ACCESS`:** `CHANGE_NOTIFY`,
  `CHECK_UNPROCESSED_VOLUMES`, `VOLUME_ARRIVAL_NOTIFICATION`, and
  `TRACELOG_CACHE`.
- **Only the queries are `FILE_ANY_ACCESS`:** `QUERY_POINTS`,
  `QUERY_DOS_VOLUME_PATH(S)`, and `QUERY_AUTO_MOUNT`.

(The mingw-w64 copy also carries two Wine-only codes, `DEFINE_UNIX_DRIVE` and
`QUERY_UNIX_DRIVE`. They are not Windows IOCTLs, and even so they require read or
read/write access.) The I/O manager compares the handle's granted access with the
IOCTL's required access before the driver sees the request. `FILE_READ_ACCESS`
is `FILE_READ_DATA` and `FILE_WRITE_ACCESS` is `FILE_WRITE_DATA`. The
`0x00100080` mask contains neither, so no handle the child can open satisfies any
state-changing or notification IOCTL.

**Exposure.** The child can issue the `FILE_ANY_ACCESS` queries. They reveal the
host's volume, mount-point, and drive-letter layout, plus the automount setting.
That read-only disclosure is the accepted cost of this opt-in. The opt-in shares
the retirement criterion of the `NUL` ACE: remove it once Git for Windows no longer
needs the mount manager to resolve its working directory inside an AppContainer.

## Public-repository privacy rules (enforced)

This repo is public. It must never contain the operational specifics of any real
deployment or workstation. The following are **prohibited in code, docs, tests,
fixtures, comments, and commit messages**:

- Real hostnames, private IP addresses (RFC1918 / CGNAT), internal domains/DNS
  names, or overlay-network (mesh / tailnet) names.
- Real usernames, home paths (`/home/<user>`), personal email addresses, or
  directory realms.
- Any secret: passwords, API keys, tokens, OAuth client secrets, private keys,
  certificate private halves, or signing seeds.

> **Note on the net enforcer.** `agent-bridle-tool-web` is the SSRF/`net` enforcer,
> so it legitimately *names* the private ranges it blocks (`10.0.0.0/8`,
> `192.168.0.0/16`, `169.254.169.254`, …). Those generic range identifiers are
> allowlisted; a real operational *host* (a non-zero host part) is still caught.

Use **placeholders only**: `example.com` / `example.lan`, `192.0.2.0/24`
(TEST-NET-1), `198.51.100.0/24`, `203.0.113.0/24`, `user@example.com`.

## Enforcement

- **`security-audit` CI** (`.github/workflows/security-audit.yml`): a gitleaks
  secret scan + the internal-specifics linter
  (`scripts/check-internal-specifics.sh`). A finding **blocks the merge**.
- **Pre-commit** (`.pre-commit-config.yaml`): the same two checks run locally
  before a commit is created — see `docs/PRIVACY.md`.

## Secret handling in code

- Secrets are never committed, never logged, and never written to durable disk.
- The step-up verifier (`Ed25519Verifier`) only ever consumes *public* verifying
  keys + assertions; the only keys in the tree are fixed, non-secret **test**
  seeds (literal `[N u8; 32]` arrays in `step_up.rs`).
