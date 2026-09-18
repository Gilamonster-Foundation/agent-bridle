# agent-bridle-core

The capability-enforcement core of agent-bridle: the `Tool` trait, the `Gate`
(the single mint site for a `ToolContext`), the `Registry`, the `Sandbox`
plumbing, and the `ToolEnvelope` result type. It re-exports the canonical
authority types (`Caveats`, `Scope`, `CountBound`) from `agent-mesh-protocol`
so every host and tool speaks one lattice.

The non-bypassable invariant: a `Tool` can only act through a `ToolContext`,
and a `ToolContext` can only be minted inside `Gate::authorize`. The tool
receives the *meet* of granted-and-required authority — least authority by
construction.

- `Tool` / `Registry` — declare required `Caveats`, dispatch through the gate;
  `Registry::dispatch_with_strength_floor` binds a host-approved confinement
  minimum to the actual invocation
- `Gate` + `ToolContext` — mint-token enforcement; no public constructor
- `Sandbox` — honest `NoopSandbox` fallback plus opt-in native Landlock,
  Seatbelt, and AppContainer process boundaries
- `step_up` — human-presence step-up (the `attest` outcome): `Gate::evaluate` / `authorize_with_discharge` / `authorize_step_up`, the `DischargeProvider` ceremony seam and `DischargeVerifier` proof check. The production `Ed25519Verifier` is behind the off-by-default `verifier-ed25519` feature; WebAuthn EdDSA and ES256 assertion verifiers are behind `verifier-webauthn` and `verifier-webauthn-es256` (ADR 0007)
- Deliberately tiny dependency budget (`anyhow`, `serde`, `serde_json`, `async-trait`, `agent-mesh-protocol`); no tokio by default — heavy runtimes live in leaf tool crates. Optional, off-by-default deps include `landlock` (`linux-landlock`) and `ed25519-dalek` (`verifier-ed25519`)

## Features

| Feature | Default | Pulls | Enables |
|---|---|---|---|
| `linux-landlock` | off | `landlock` (Linux only) | filesystem confinement, direct-exec narrowing, and deny-all TCP on ABI-v4 kernels |
| `macos-seatbelt` | off | no Rust dependency | `sandbox-exec` filesystem/exec confinement; deny-all or loopback network policy with exact outbound Unix-endpoint grants |
| `windows-appcontainer` | off | companion `agent-bridle-aclaunch.exe` | AppContainer filesystem DACLs, deny-all or loopback-only network policy, and exec deny-all |
| `os-sandbox` | off | target-specific backend deps | convenience feature for every native OS sandbox backend |
| `verifier-ed25519` | off | `ed25519-dalek` | production `Ed25519Verifier` for step-up discharges |
| `verifier-webauthn` | off | `ed25519-dalek`, `sha2` | production WebAuthn EdDSA/-8 assertion verifier |
| `verifier-webauthn-es256` | off | `p256`, `sha2` | production WebAuthn ES256/-7 assertion verifier |

Coverage is scope-shaped and is surfaced per axis. Landlock's loader-trampoline
residual keeps `exec` at interceptor strength; Seatbelt confines restricted
exec; AppContainer reports exec as kernel only for deny-all. General hostname
network allowlists are not directly expressible by the native kernels and keep
their documented proxy/advisory posture. A restricted filesystem scope fails
closed when no native backend can enforce it.

On Windows, AppContainer is attached at process creation by the wired
`agent-bridle-aclaunch.exe` wrapper rather than by `Sandbox::apply` on the
current thread.

## System timezone data

The macOS read baseline includes the OS-owned timezone database, so confined
programs can follow `/etc/localtime` and `/usr/share/zoneinfo` into the standard
data files. Linux already includes its localtime file and shared runtime data.
These are read defaults in `SandboxPolicy::base_read_paths`, not write grants.
Setting `TZ` to another file never grants access to that file.

`ConfinedCommand` still starts with an empty environment. A host that inherits
the parent's explicit timezone must pass `TZ` through its existing `env` seam,
preserving absent versus empty values. The runtime interprets the value.
Windows AppContainer timezone parity is tracked in [#387](https://github.com/Gilamonster-Foundation/agent-bridle/issues/387);
micro-VM named-zone materialization is tracked in [#388](https://github.com/Gilamonster-Foundation/agent-bridle/issues/388).

## Proposed 0.7 maintenance scope

This candidate extends the published 0.7.15 API with explicit private-host and
Unix-endpoint approvals. It retains that line's admission behavior for existing
scopes; a compatible published release still requires upstream review and
validation. The workspace version is unchanged.

This is not a port of the 0.8 admission protocol and does not relax its macOS
restricted-network hold or establish that its outstanding confinement proof is
complete. Consumers requiring that protocol must retain its refusal until the
separate admission work is accepted.

## Exact private-host approvals for async subprocesses

On Unix, with `spawn-tokio`, an owning harness may call
`ConfinedCommand::with_private_hosts(["service.example".to_string()])?`
before `spawn_tokio`. This separate, transient approval lets that exact name
resolve to RFC1918 or IPv6 unique-local space only when the active context's
ordinary network allowlist also permits it. Supply names approved by the
operator, never names taken from tool output or server metadata.

The default is empty. Wildcards, URLs, ports and malformed names are rejected;
DNS names use ASCII/ACE labels with case and final-dot normalization. Metadata,
link-local, unspecified, multicast and CGNAT destinations remain blocked.
The existing proxy resolves each connection once and dials that screened
address. Its kernel loopback fence and the command's filesystem/exec caveats
are unchanged. Platforms without that fence retain their documented advisory
posture; this option does not enable a proxy or alter synchronous `spawn`.

`net_proxy::start_with_private_hosts` exposes the same policy for embedders
already using the proxy's resolver/audit seams. Existing constructors retain
the default private-address denial.

## Exact Unix socket endpoints (macOS Seatbelt)

An explicit `net` scope entry `unix:/absolute/canonical/service.sock` permits
outbound connections to that existing Unix-domain socket only. The path must
already be canonical and name a socket; relative paths, symlinks, missing paths,
and patterns fail closed. Filesystem read/write authority stays independent.
The ordinary capability meet retains or removes this exact token like any other
net grant; a filesystem grant alone never creates socket authority.

A socket-only scope denies all IP connections. Mixed loopback/socket scopes
retain the loopback fence, while mixed remote-host/socket scopes require the
managed async egress proxy. Unix entries never enter its DNS host allow-list.
Other backends reject these grants, including at the advisory strength floor.
There is no all-Unix grant, implicit socket-directory grant, or permission to
listen. Existing scopes without a Unix entry keep their previous behavior.

This authorizes access to a trusted endpoint, not every operation its service
can perform. It does not mediate application messages or descriptor delegation
through that connection. The grant names a pathname, not a daemon or inode
identity: replacing the socket at that approved path changes the peer. The
service's own authorization boundary and ownership of its directory still matter.

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0

Model: GPT-6 | Harness: Codex CLI v0.154.0 | Operator: S Hartsock | Time: 11:46 EDT | Date: 2026-09-17

Model: GPT-6 | Harness: Codex CLI v0.154.0 | Operator: S Hartsock | Time: 21:43 EDT | Date: 2026-09-17
