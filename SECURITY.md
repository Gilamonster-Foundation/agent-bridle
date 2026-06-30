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
  #57) — keep the read scope tight in the meantime.

> A future `linux-seccomp` backstop (ADR 0011 D4) could deny the mount/namespace
> syscall family in-process as defense-in-depth for the bind-mount case. It needs
> a hand-rolled, arch-guarded BPF filter — a single `seccompiler` `mismatch_action`
> cannot keep the wrong-arch guard distinct from the permissive default a denylist
> requires (the i386/x32 bypass) — so it must be authored and verified on a real
> Landlock+seccomp host; tracked under #57/#35. The host-sysctl mitigation above
> closes the same gap today, and a strong principal already fails closed regardless.

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
