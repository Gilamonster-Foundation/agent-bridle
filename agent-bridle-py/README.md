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
use the leashed tool registry as an ordinary library. The maturin wheel compiles
the Rust in, so the confined **argv + safe-subset** shell (ADR 0005) ships inside
the wheel.

## Usage

```python
import agent_bridle

# Successful external spawning in the stock wheel requires an explicit ambient
# grant because the wheel does not enable a native L3 sandbox backend.
full_authority = {
    "exec": "all",
    "fs_read": "all",
    "fs_write": "all",
    "net": "all",
    "max_calls": "unlimited",
    "valid_for_generation": "all",
}
r = agent_bridle.invoke(
    "shell", {"program": "echo", "args": ["hi"]}, full_authority
)
print(r["exit_code"], repr(r["stdout"]))   # -> 0 'hi\n'
print(r["sandbox_kind"])                    # -> 'none' (default wheel enables no native L3 backend)

# DENIED: restricted external spawns fail closed without a native backend,
# even when the named program is inside the L2 exec allowlist.
restricted = {**full_authority, "exec": {"only": ["echo"]}}
try:
    agent_bridle.invoke("shell", {"program": "echo", "args": ["held"]}, restricted)
except agent_bridle.BridleDenied as e:   # subclass of PermissionError
    print("blocked by the leash:", e)

# Inspect the registry.
print(agent_bridle.tool_names())          # -> ['shell']
print(agent_bridle.tool_definitions())    # MCP tools/list schemas
```

### The `shell` tool accepts argv and parsed safe-subset forms

The shell tool accepts explicit **argv form** —
`{"program": ..., "args": [...]}` — and the parsed safe-subset
`{"cmd": "echo hi"}` compatibility form. The safe-subset parser rejects shell
control syntax before execution. Both forms pass through L2 authority checks and
native-backend admission; stock wheels therefore refuse restricted external
spawns because they ship without a native L3 sandbox backend.

## API

| Function | Signature | Notes |
|---|---|---|
| `invoke` | `invoke(tool: str, args: dict, caveats: dict \| None = None) -> dict` | Dispatch `tool` with `args` under `caveats`. `None` means deny-all. Ambient authority must be granted explicitly. Returns the result dict; raises `BridleDenied` on a leash denial or any tool error. |
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

Any omitted axis defaults to its **bottom** (deny-all). A full serialized Rust
`Caveats` value names every axis, so it round-trips without relying on defaults.

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

Apache-2.0. This default wheel carries the safe-subset engine, not the optional
Brush dependencies; the workspace `NOTICE` covers builds that do carry Brush.
