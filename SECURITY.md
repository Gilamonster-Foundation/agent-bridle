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

## Known security issue: opt-in AppContainer `NUL` device ACE

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
