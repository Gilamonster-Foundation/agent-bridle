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
- Compiles with the `shell` feature off (exposing nothing), so workspaces build
  under `--no-default-features`
- No `brush` dependency. `brush-bridle-core` (a renamed brush fork published to
  crates.io) is the **deferred, reversible** full-bash alternative engine behind
  the same registry seam (ADR 0005 D4) — adopted under its own optional feature
  if/when needed, not shipped today (#20/#28).

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
