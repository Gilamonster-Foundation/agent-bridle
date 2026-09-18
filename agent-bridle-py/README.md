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

# Restrict executable selection to echo. The other axes are explicitly open:
# this default-wheel example enables no native filesystem/network sandbox.
grant = {
    "exec": {"only": ["echo"]},
    "fs_read": "all",
    "fs_write": "all",
    "net": "all",
    "max_calls": "unlimited",
    "valid_for_generation": "all",
}

# ALLOWED: `echo` is within the granted `exec` scope, so it is spawned as an
# external program (after the exec leash admits it) and stdout is captured.
r = agent_bridle.invoke("shell", {"program": "echo", "args": ["hi"]}, grant)
print(r["exit_code"], repr(r["stdout"]))   # -> 0 'hi\n'
print(r["sandbox_kind"])                    # -> 'none' (default wheel enables no native L3 backend)

# DENIED: even a harmless `pwd` is outside the exact executable grant.
try:
    agent_bridle.invoke("shell", {"program": "pwd", "args": []}, grant)
except agent_bridle.BridleDenied as e:   # subclass of PermissionError
    print("blocked by the leash:", e)

# Inspect the registry.
print(agent_bridle.tool_names())          # -> ['shell']
print(agent_bridle.tool_definitions())    # MCP tools/list schemas
```

### Shell input forms

The shell accepts either `{"program": ..., "args": [...]}` or a safe-subset
`{"cmd": "echo hi"}` string, one form per call. The safe-subset parser checks
executable and filesystem operations before spawning; unsupported dynamic
syntax is refused. See the [shell documentation](../agent-bridle-tool-shell/README.md).

The example explicitly leaves all non-exec axes unrestricted to match the
default wheel, which compiles no native L3 backend. Restricting a filesystem or
network axis can therefore require a backend that this build cannot provide;
omitting that axis does not authorize it.

## API

| Function | Signature | Notes |
|---|---|---|
| `invoke` | `invoke(tool: str, args: dict, caveats: dict \| None = None) -> dict` | Dispatch `tool` with `args` under `caveats`. `None` → deny-all; no operation is authorized. Returns the result dict; raises `BridleDenied` on a leash denial or any tool error. |
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

Any omitted axis defaults to **deny-all**: scopes become empty and a missing
`max_calls` becomes zero. A complete `serde_json::to_value(&Caveats)` grant
names every axis and round-trips unchanged.

> **Interop note.** The `agent_mesh.core.Caveats` *pyclass* (agent-mesh PR #18)
> exposes a friendlier surface (`fs_read=["/repo"]`, `max_calls=10`, top axes as
> `None`). Its `.to_json()` is **not** byte-identical to the Rust serde shape
> above. Translate scope values explicitly (`["echo"]` → `{"only": ["echo"]}`,
> a top-valued `None` → `"all"`) and bounds (`10` → `{"at_most": 10}`,
> an unlimited bound → `"unlimited"`). Do not omit a top-valued axis: omission
> means deny-all at this Python boundary.

A malformed grant (unknown axis, wrong value form) raises `ValueError` — it is
bad input, distinct from a `BridleDenied` authority refusal.

## Building from source

Build in an isolated virtual environment:

```bash
python3 -m venv /tmp/abp-venv
/tmp/abp-venv/bin/pip install 'maturin>=1.7,<2' pytest
/tmp/abp-venv/bin/maturin develop --manifest-path agent-bridle-py/Cargo.toml
/tmp/abp-venv/bin/pytest agent-bridle-py/tests/ -v
```

## License

Apache-2.0. This default wheel carries the safe-subset engine, not the optional
Brush dependencies; the workspace `NOTICE` covers builds that do carry Brush.

Model: GPT-6 | Harness: Codex CLI v0.154.0 | Operator: S Hartsock | Time: 00:18 EDT | Date: 2026-09-18
