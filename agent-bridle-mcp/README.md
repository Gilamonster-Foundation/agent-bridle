# agent-bridle-mcp

An MCP (Model Context Protocol) stdio server over the agent-bridle
capability-governed tool registry. Any MCP client (e.g. `claude mcp add`, or a
host's `mcp_servers:` config) can drive this binary over stdio and call the
Caveats-confined Rust tools; the server speaks newline-delimited JSON-RPC 2.0
and handles `initialize`, `tools/list`, `tools/call`, and `shutdown`/`exit`.

The leash is real and configurable: the session's granted `Caveats` come from
`$AGENT_BRIDLE_CAVEATS` (JSON), else `~/.agent-bridle/config.toml` `[caveats]`,
else a loudly reported deny-all default. Every `tools/call` is dispatched
through the registry against that grant, so the leash holds *through* the MCP
boundary.

- `carried-coreutils` feature (default-on): serves the authenticated
  sandbox-worker Brush shell with bundled `ls`/`cat`/`echo`/`head`/`sort`/`wc`
  on Linux/macOS; targets without the private transport advertise the
  safe-subset shell instead
- `shell` feature (off by default): selects the lean argv + safe-subset shell
  when default features are disabled
- `web` feature (off by default): serves the confined `web_fetch` tool
- `os-sandbox` feature (off by default): compiles all native L3 backends and
  selects Landlock, Seatbelt, or AppContainer for the target OS; official
  release binaries enable this feature
- `--no-default-features` yields a valid but empty registry

The default feature set provides the carried worker-local L2 interceptor but
does not compile a native L3 backend. Reproduce the official release posture
with `cargo build -p agent-bridle-mcp --release --features os-sandbox`.

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
