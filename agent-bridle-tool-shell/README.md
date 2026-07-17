# agent-bridle-tool-shell

A capability-confined shell tool for agent-bridle — the **argv + safe-subset
engine** (ADR 0005). agent-bridle *is* the exec funnel: it parses the request
itself, checks the `exec`/`fs` leash, spawns the program(s) directly, and
**refuses the dynamic constructs by design** (`$(…)`, backticks, subshells,
`eval`). The tool accepts two input shapes:

- argv form (`program` + `args`), and
- free-form `cmd` — a safe subset: pipelines (`|`), redirections
  (`>`/`>>`/`<`/`2>`/`2>&1`), `&&`/`||`/`;` sequencing, filename globbing
  (`*`/`?`/`[…]`), and allowlisted `$VAR` expansion.

Because agent-bridle performs each redirect's open and each glob's directory
listing itself, those filesystem touches are leash-checked (`fs_read`/`fs_write`)
**before any stage spawns**; out-of-scope `exec` is denied at the funnel.

This is the **L2 convenience** layer. The object-capability **boundary** is L3
(ADR 0005): on a capable Linux build (`linux-landlock`) with `fs_write`
restricted, the engine applies a kernel-enforced Landlock ruleset before
spawning and the result reports `SandboxKind::Landlock`; otherwise the run is
**honestly advisory** and reports `SandboxKind::None` — never overclaiming (the
per-axis report refines this further, ADR 0004 D1). The cross-OS L3 strategy is
ADR 0009 (#78/#35/#50/#51/#57).

- `ShellTool` — the registry tool, gated by the `exec`/`fs` axes of `Caveats`
- Compiles with the `shell` feature off (exposing only the lightweight observer
  contract), so workspaces build under `--no-default-features`
- No `brush` dependency. `brush-bridle-core` (a renamed brush fork published to
  crates.io) is the **deferred, reversible** full-bash alternative engine behind
  the same registry seam (ADR 0005 D4) — adopted under its own optional feature
  if/when needed, not shipped today (#20/#28).

## Live output observation

`ShellTool`, `HostShellTool`, and `BrushShellTool` each provide a
`with_output_observer` construction-time builder. The shared
`ShellOutputObserver` receives bounded raw-byte chunks tagged with a process-local
`ShellInvocationId` and `ShellOutputStream::Stdout` or
`ShellOutputStream::Stderr`. Distinct IDs keep concurrent dispatches separate.
The top-level `agent-bridle` facade re-exports all three observer types whenever
any shell-engine feature is enabled.
The ordinary `Registry::dispatch` and `Tool::invoke` paths are unchanged, so
observation adds no authority and cannot bypass the gate.

Chunks may split UTF-8 code points. Callbacks run on a dedicated presentation
thread, so slow observer code cannot stall child pipes, timeout, or cancellation.
Callbacks for one ID are serialized, but different IDs use different presentation
threads and may enter the same observer concurrently. On ordinary completion,
`on_finish(id)` follows every queued `on_output` call for that ID; dispatch does
not wait for it. Cancellation stops accepting new chunks, though a callback
already dequeued may finish afterward. Callback panics are contained.

At most the configured output cap is delivered per stream. This is a live view,
not a replacement result: separate safe-shell pipeline stderr readers follow
live reader scheduling, while the completed envelope assembles stderr in
pipeline-stage order and then applies its cap. The two can differ, and the
completed envelope is authoritative. Excess host/brush output is drained and
discarded to preserve child behavior without unbounded capture.

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
