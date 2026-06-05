# agent-bridle-tool-shell

A capability-confined, brush-backed shell tool for agent-bridle. brush is the
carried, batteries-included shell/coreutils runtime ("the hands"); this crate
puts it on the agent-bridle-core leash. The tool accepts two input shapes:
argv form (`program` + `args`) and free-form `cmd` (an `sh -c`-style command
string with pipelines, redirections, `&&`, globbing).

Both shapes are confined *in-process* by the `CaveatInterceptor`, which rides
the `CommandInterceptor` exec/open hook in our brush fork: it fires at the
single external-spawn funnel and at every file open (redirections, `source`),
so free-form scripts are gateable too. Landlock remains the authoritative
Linux backstop; off-Linux the in-process hook is the enforcement.

- `ShellTool` — the registry tool, gated by the `exec` axis of `Caveats`
- `CaveatInterceptor` — in-process exec/open confinement inside brush
- Compiles with the `shell` feature off (exposing nothing), so workspaces build under `--no-default-features`

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
