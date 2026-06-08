# agent-bridle-tool-shell

The agent-bridle `shell` tool.

> **⚠️ Currently a fail-closed STUB.** The brush-backed, capability-confined
> shell (which gated commands in-process via a `CommandInterceptor` exec/open
> hook in a brush fork) depended on a **git** dependency, and crates.io forbids
> git sources in a published manifest. To unblock publishing, the brush deps and
> the confined implementation were removed; the confined impl is preserved in
> git history and returns when the brush hook is upstreamed into `reubeno/brush`
> (see the workspace `CHANGELOG`).

The published default `shell` tool **denies every invocation and spawns
nothing**. A consumer who needs to run commands opts in explicitly — there is no
confined middle ground until brush lands:

- `ShellTool::stub()` (= `new()`, `Default`) — **Denied**. The safe default;
  `agent_bridle::registry()` builds this.
- `ShellTool::insecure_bash(hook)` — runs `bash -lc <command>` (falling back to
  `sh -c`) **UNCONFINED**, but only after an `ApprovalHook::approve` returns
  true. Reported honestly as `sandbox_kind: none`.
- `ShellTool::dangerous_unconfined()` — the same UNCONFINED bash with no approval
  gate. Development only.

The host wires these to `agent-bridle-mcp`'s `--insecure` (per-command approval
on `/dev/tty`) and `--dangerously-allow-all` flags via
`agent_bridle::registry_with_shell`.

The tool's input schema is stable for when the confined shell returns: argv form
(`program` + `args`) or free-form `cmd` (an `sh -c`-style string). The crate
compiles with the `shell` feature off (exposing nothing), so workspaces build
under `--no-default-features`.

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
