# agent-bridle (Python)

**The capability leash for agent tools, callable in-process from Python.**

`pip install agent-bridle` lays down a single native PyO3 extension module
(`import agent_bridle`) that dispatches tools through the same
`agent_mesh_protocol::Caveats` leash the Rust hosts use. Every call flows through
the registry's `Gate`, which mints the tool's context from the **meet** of
granted-and-required authority — least authority by construction. An
out-of-scope dispatch is refused *before the tool runs* and surfaces as
`agent_bridle.BridleDenied` (a subclass of the built-in `PermissionError`).

This is **Pillar A** of the agent-bridle Python story (see `docs/DESIGN.md` §8):
use the leashed tool registry as an ordinary library.

> **⚠️ The `shell` tool is currently a fail-closed STUB.** The brush-backed
> confined shell depended on a *git* fork of brush (forbidden by crates.io), so
> it was removed to unblock publishing; it returns when the brush hook is
> upstreamed (see the workspace `CHANGELOG`). Through this wheel, the `shell`
> tool **denies every invocation and spawns nothing**, raising `BridleDenied`.
> The leash mechanics (gate, budget, generation) and the `web_fetch` `net`
> enforcer are unaffected. The opt-in UNCONFINED bash escalation
> (`registry_with_shell`) is a Rust-host concern (`--insecure` /
> `--dangerously-allow-all` on `agent-bridle-mcp`), not exposed by this wheel.

## Usage

```python
import agent_bridle

grant = {"exec": {"only": ["echo"]}}

# The `shell` tool is the fail-closed stub: it denies and spawns nothing,
# regardless of the grant, raising BridleDenied (a subclass of PermissionError).
try:
    agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]}, grant)
except agent_bridle.BridleDenied as e:
    print("shell is a stub:", e)  # mentions --insecure / --dangerously-allow-all

# A registry miss is also a BridleDenied.
try:
    agent_bridle.invoke("no_such_tool", {}, grant)
except agent_bridle.BridleDenied as e:
    print("no such tool:", e)

# Inspect the registry — the `shell` tool is present (as the stub) with its
# stable input schema.
print(agent_bridle.tool_names())          # -> ['shell']
print(agent_bridle.tool_definitions())    # MCP tools/list schemas
```

### The `shell` tool's input shape (stable across the stub change)

The shell tool accepts **argv form** — `{"program": ..., "args": [...]}` — or a
free-form `{"cmd": "..."}` string. The argv form names a discrete program token;
the confined shell (when it returns) gates on it via the `exec` caveat and
confines free-form scripts in-process. The stub denies both shapes.

## API

| Function | Signature | Notes |
|---|---|---|
| `invoke` | `invoke(tool: str, args: dict, caveats: dict \| None = None) -> dict` | Dispatch `tool` with `args` under `caveats`. `None` → unconfined (`Caveats::top()`) with a stderr WARNING. Returns the result dict; raises `BridleDenied` on a leash denial or any tool error. |
| `tool_names` | `tool_names() -> list[str]` | Registered tool names (sorted). |
| `tool_definitions` | `tool_definitions() -> list[dict]` | One MCP `tools/list` dict (`name` + `inputSchema`) per tool. |
| `BridleDenied` | exception class | Subclass of `PermissionError`; its message carries the human-readable denial reason. |

## Caveats shape

`caveats` is an ordinary Python `dict` in the **agent-mesh-protocol Rust
`Caveats` serde shape** — you do **not** need to `import agent_mesh`. Each axis:

| Axis | Value |
|---|---|
| `fs_read` / `fs_write` / `exec` / `net` | `"all"` or `{"only": ["item", …]}` |
| `max_calls` | `"unlimited"` or `{"at_most": N}` |
| `valid_for_generation` | `"all"` or `{"only": [N, …]}` (non-negative integers) |

Any omitted axis defaults to its **top** (unrestricted). This is exactly the
shape `serde_json::to_value(&Caveats)` produces in Rust.

> **Interop note.** The `agent_mesh.core.Caveats` *pyclass* (agent-mesh PR #18)
> exposes a friendlier surface (`fs_read=["/repo"]`, `max_calls=10`, top axes as
> `None`). Its `.to_json()` is **not** byte-identical to the Rust serde shape
> above; translate each axis (`["echo"]` → `{"only": ["echo"]}`, `None` → omit,
> `10` → `{"at_most": 10}`) when passing an agent-mesh pyclass grant here. Both
> describe the same lattice; only the JSON spelling differs.

A malformed grant (unknown axis, wrong value form) raises `ValueError` — it is
bad input, distinct from a `BridleDenied` authority refusal.

## Building from source

The shared `~/venv` may carry too old a maturin; build in an isolated venv:

```bash
python3 -m venv /tmp/abp-venv
/tmp/abp-venv/bin/pip install 'maturin>=1.7,<2' pytest
/tmp/abp-venv/bin/maturin develop --manifest-path agent-bridle-py/Cargo.toml
/tmp/abp-venv/bin/pytest agent-bridle-py/tests/ -v
```

## License

Apache-2.0. The brush dependency (MIT) is currently removed (the confined shell
is stubbed pending an upstream merge); its notice is retained in the workspace
`NOTICE` for when the brush-backed shell returns.
