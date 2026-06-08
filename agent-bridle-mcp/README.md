# agent-bridle-mcp

An MCP (Model Context Protocol) stdio server over the agent-bridle
capability-governed tool registry. Any MCP client (e.g. `claude mcp add`, or a
host's `mcp_servers:` config) can drive this binary over stdio and call the
Caveats-confined Rust tools; the server speaks newline-delimited JSON-RPC 2.0
and handles `initialize`, `tools/list`, `tools/call`, and `shutdown`/`exit`.

The leash is real and configurable: the session's granted `Caveats` come from
`$AGENT_BRIDLE_CAVEATS` (JSON), else `~/.agent-bridle/config.toml` `[caveats]`,
else a loudly-warned unconfined default. Every `tools/call` is dispatched
through the registry against that grant, so confinement holds *through* the
MCP boundary.

- `shell` feature (default-on): serves the `shell` tool. With no CLI flag it is
  the **fail-closed stub** (deny-only) — the brush-backed confined shell is
  pending an upstream merge (see the workspace `CHANGELOG`). Opt in to an
  UNCONFINED bash with `--insecure` (per-command approval prompted on `/dev/tty`,
  never stdin) or `--dangerously-allow-all` (no gate; development only).
- `web` feature (off by default): serves the confined `web_fetch` tool (still
  fully confined: host allowlist + SSRF screen + per-redirect re-check + IP pin)
- `--no-default-features` yields a valid but empty registry

Part of [agent-bridle](https://github.com/Gilamonster-Foundation/agent-bridle),
the capability leash for agent tools — a shared, capability-governed tool
registry for the Gilamonster agent line.

## License

Apache-2.0
