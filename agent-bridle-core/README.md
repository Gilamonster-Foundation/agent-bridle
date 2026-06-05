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

- `Tool` / `Registry` — declare required `Caveats`, dispatch through the gate
- `Gate` + `ToolContext` — mint-token enforcement; no public constructor
- `Sandbox` — advisory `NoopSandbox` everywhere; kernel-enforced `LandlockSandbox` on Linux under the `linux-landlock` feature
- Deliberately tiny dependency budget (`anyhow`, `serde`, `serde_json`, `async-trait`, `agent-mesh-protocol`); no tokio — heavy runtimes live in leaf tool crates

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
