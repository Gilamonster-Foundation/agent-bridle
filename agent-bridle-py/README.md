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

# A grant that authorizes executing ONLY `echo` — nothing else.
grant = {"exec": {"only": ["echo"]}}

# ALLOWED: `echo` is within the granted `exec` scope, so it is spawned as an
# external program (after the exec leash admits it) and stdout is captured.
r = agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]}, grant)
print(r["exit_code"], repr(r["stdout"]))   # -> 0 'hi\n'
print(r["sandbox_kind"])                    # -> 'none' (advisory off-Linux; P0)

# DENIED: `rm` is NOT in the granted `exec` scope. The leash refuses to mint
# the tool's context, so the destructive command never runs — no prompt
# hygiene required. The confused-deputy gap is closed structurally.
try:
    agent_bridle.invoke("shell", {"program": "rm", "args": ["-rf", "/tmp/x"]}, grant)
except agent_bridle.BridleDenied as e:   # subclass of PermissionError
    print("blocked by the leash:", e)

# Inspect the registry.
print(agent_bridle.tool_names())          # -> ['shell']
print(agent_bridle.tool_definitions())    # MCP tools/list schemas
```

### The `shell` tool takes argv form, not a `cmd` string

The shell tool's arguments are **argv form** — `{"program": ..., "args": [...]}`
— deliberately, not a free-form `{"cmd": "echo hi"}` string. The `exec` caveat
gates on the *named program token*, so the program has to be a discrete field the
leash can check. A `cmd` string would let `echo hi; rm -rf /` slip the leash,
which is exactly the hole the bridle closes (DESIGN §6).

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

Apache-2.0. The deferred, optional `brush` engine (#20) is MIT — its notice is
carried in the workspace `NOTICE` for when it is adopted.
