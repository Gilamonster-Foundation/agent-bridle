# strands-bridle (draft / experiment)

**A [Strands](https://github.com/strands-agents/harness-sdk) sandbox that runs
a harness's shell commands, file tools and code under one agent-bridle grant.**

> **Status: experiment, in this repo only.** Like `pi-bridle`, this is a draft
> to prove the leash against a second, independent harness. It is outside the
> Cargo workspace, not published, and not wired into CI.

## What it does

Strands tools reach the machine through a `Sandbox`. `PosixShellSandbox`
implements every operation (`read_file`, `write_file`, `list_files`,
`remove_file`, `execute_code`) as shell commands, and asks a subclass for one
primitive: `execute_streaming`.

`BridleSandbox` implements that primitive as a JSON-RPC client of one
`agent-bridle-mcp` subprocess per sandbox:

```
Strands tool ──► Sandbox.read_file / write_file / execute / execute_code
                      │  PosixShellSandbox turns each into a shell command
                      ▼
               BridleSandbox.execute_streaming
                      │  tools/call { name: "shell", arguments: { cmd, cwd, env, timeout_secs } }
                      ▼
               agent-bridle-mcp ──► Caveats check ──► Brush worker under the OS fence
```

So a stock harness runs under the grant with no change to its tools:

```python
from strands_bridle import BridleSandbox

async with BridleSandbox() as sandbox:          # starts agent-bridle-mcp
    await sandbox.write_file("notes/todo.txt", b"ship it\n")
    result = await sandbox.execute("ls notes")
    print(result.stdout, sandbox.last_envelope["sandbox_kind"])
```

## The grant

The server sources the grant as it always does: `$AGENT_BRIDLE_CAVEATS` (JSON),
else `~/.agent-bridle/config.toml` `[caveats]`, else deny-all. Nothing here
decides authority. Pass `env=` to give one sandbox its own grant.

The inherited helpers use heredocs and `$(dirname ...)`. The safe-subset engine
refuses those and the host engine refuses any restricted `exec`, so the grant
needs the **Brush** engine, the server's default on Linux and macOS.

Grant `exec` for what the helpers run, plus each interpreter you want
`execute_code` to use:

```json
{
  "fs_read": "all",
  "fs_write": { "only": ["/work"] },
  "exec": { "only": ["base64", "dirname", "mkdir", "rm", "env", "ls", "python3"] },
  "net": { "only": [] },
  "max_calls": "unlimited",
  "valid_for_generation": "all"
}
```

## How results map

| Bridle result | What the harness sees |
|---|---|
| command ran | `ExecutionResult(exit_code, stdout, stderr)` |
| `timed_out` | `SandboxTimeoutError`, with the partial output |
| `stdout_truncated` / `stderr_truncated` | `OSError`: the result is incomplete |
| the leash refused something | exit code 126, the reason on stderr, what ran before it on stdout |
| refused before it ran (budget, unknown tool) | exit code 126 and the reason |

`sandbox.last_envelope` holds the full envelope of the last command: the typed
`denials`, `sandbox_kind`, and the per-axis `enforcement` report.

When the task running a command is cancelled, the sandbox sends
`notifications/cancelled` and the server kills and reaps the worker. This side
never sends a kill.

## Limits

- **Output arrives at the end.** The server returns one result per command, so
  `execute_streaming` yields the output once, when the command ends.
- **The capture cap bounds `read_file`.** A file whose base64 form passes the
  server's cap (`[bridle.limits] max_output_bytes`, 1 MiB by default) raises
  `OSError`. It never returns a short file.
- **A request is capped at 1 MiB.** `write_file` and `execute_code` send their
  content inside the command, so content near 750 KiB or more fails.
- **One grant per sandbox.** To give a sub-agent a narrower grant, give it its
  own `BridleSandbox` with its own `env`.
- **No `cancel_signal`.** The Strands sandbox API (1.61) has no such parameter;
  cancellation follows the task.

## Setup (manual, for our own evaluation)

```bash
cargo build -p agent-bridle-mcp          # target/debug/agent-bridle-mcp
export STRANDS_BRIDLE_MCP_BIN=$PWD/target/debug/agent-bridle-mcp
pip install strands-agents pytest pytest-asyncio
cd integrations/strands-bridle && python -m pytest
```

`tests/test_strands_bridle.py` runs against a scripted JSON-RPC peer and needs
no binary. `tests/test_real.py` drives the real server and is skipped when the
binary is not built.

## Files

- `strands_bridle.py`: `BridleSandbox` and its JSON-RPC client.
- `tests/fake_peer.py`: the scripted peer the unit tests talk to.
- `pyproject.toml`: metadata and the pytest configuration. Not published.
