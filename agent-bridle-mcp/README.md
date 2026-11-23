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
- `os-sandbox` feature (default-on): compiles all native L3 backends and
  selects Landlock, Seatbelt, or AppContainer for the target OS. Each backend
  is inert off its own OS
- `--no-default-features` yields a valid but empty registry

The default feature set is the release posture: the carried worker-local L2
interceptor plus the native L3 backend for the target OS. Without a compiled
backend, an fs-restricted grant is refused, because nothing can meet the
kernel filesystem floor.

Mechanism is configured apart from the grant, in the `[bridle]` table of the
same `~/.agent-bridle/config.toml` or through `BRIDLE_*` environment
variables:

```toml
[bridle.shell]
engine = "safe-subset"   # or "brush" / "host"; unset keeps the default rule

[bridle.gate.default_strength_floor]
exec = "interceptor"     # the floor every tools/call is dispatched with;
net = "kernel"           # the filesystem axes always require the kernel
```

A setting this build cannot honor fails startup: an unknown engine, an engine
that is not compiled in, a config file that exists but cannot be read, or the
old scalar form of the floor. It is never replaced by a default.

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
