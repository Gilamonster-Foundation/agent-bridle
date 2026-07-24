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
- `step_up` — human-presence step-up (the `attest` outcome): `Gate::evaluate` / `authorize_with_discharge` / `authorize_step_up`, the `DischargeProvider` ceremony seam and `DischargeVerifier` proof check. The production `Ed25519Verifier` is behind the off-by-default `verifier-ed25519` feature (ADR 0007)
- Deliberately tiny dependency budget (`anyhow`, `serde`, `serde_json`, `async-trait`, `agent-mesh-protocol`); no tokio by default — heavy runtimes live in leaf tool crates. Optional, off-by-default deps include `landlock` (`linux-landlock`) and `ed25519-dalek` (`verifier-ed25519`)

## Features

| Feature | Default | Pulls | Enables |
|---|---|---|---|
| `linux-landlock` | off | `landlock` (Linux only) | filesystem confinement, direct-exec narrowing, and deny-all TCP on ABI-v4 kernels |
| `macos-seatbelt` | off | no Rust dependency | `sandbox-exec` filesystem/exec confinement and deny-all or loopback-only network policy |
| `windows-appcontainer` | off | companion `agent-bridle-aclaunch.exe` | AppContainer filesystem DACLs, deny-all or loopback-only network policy, and exec deny-all |
| `os-sandbox` | off | target-specific backend deps | convenience feature for every native OS sandbox backend |
| `verifier-ed25519` | off | `ed25519-dalek` | production `Ed25519Verifier` for step-up discharges |

Coverage is scope-shaped and is surfaced per axis. Landlock's loader-trampoline
residual keeps `exec` at interceptor strength; Seatbelt confines restricted
exec; AppContainer reports exec as kernel only for deny-all. General hostname
network allowlists are not directly expressible by the native kernels and keep
their documented proxy/advisory posture. A restricted filesystem scope fails
closed when no native backend can enforce it.

On Windows, AppContainer is attached at process creation by the wired
`agent-bridle-aclaunch.exe` wrapper rather than by `Sandbox::apply` on the
current thread.

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
