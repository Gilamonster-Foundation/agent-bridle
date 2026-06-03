# agent-bridle

**The capability leash for agent tools.** `agent-bridle` is the shared tool +
capability-enforcement layer for the Gilamonster agent line (newt, gilamonster,
Monty, hermes-thoon). It turns each host's hand-wired, ambient-authority tool
surface into an extensible, **capability-governed registry**.

> **brush** = the hands. **`Caveats`** = the leash. **bridle** = the enforcer
> that binds them.

Every tool declares the authority it needs as an
[`agent_mesh_protocol::Caveats`] requirement. The registry refuses to dispatch
unless `required ⊑ granted` under the meet-semilattice, and hands the tool only
the **meet** of granted-and-required — least authority by construction. The
confused-deputy gap (an LLM picking tool arguments while holding full ambient
authority) is closed **structurally**, not by prompt hygiene:

- A `ToolContext` is a **mint-token**: its fields are private and it is
  constructible *only* inside `Gate::authorize`. A `Tool` cannot run without one,
  so the only path to running a tool runs through the leash.
- Effective authority is `granted.meet(tool.required())` — provably
  non-amplifying (the lattice law is property-tested upstream).

## Thesis

A tool harness is a [confused deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem):
it holds full ambient authority while taking instructions from an untrusted
source. Hardening the prompt does not fix this; it is an *architecture* problem.
`agent-bridle` makes the fix structural — attenuated capabilities, delegated
attenuation-only, with enforcement minted at a single choke point and (on Linux)
backstopped by Landlock. The tool you ship can only ever do what its leash
permits.

## Usage

```rust
use agent_bridle::registry;
use agent_bridle_core::{Caveats, CountBound, Scope};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Build the default registry (shell tool included under `--features shell`).
    let reg = registry();

    // Grant a tightly-scoped leash: may only exec `echo`, at most twice.
    let granted = Caveats {
        exec: Scope::only(["echo".to_string()]),
        max_calls: CountBound::AtMost(2),
        ..Caveats::top()
    };

    // ALLOWED: echo is in scope, budget available.
    let out = reg
        .dispatch(
            "shell",
            serde_json::json!({ "program": "echo", "args": ["hello"] }),
            &granted,
        )
        .await?;
    println!("{out}"); // -> { "exit_code": 0, "stdout": "hello\n", ... }

    // DENIED: `rm` is not in the granted `exec` scope. The leash refuses
    // before the tool ever runs — no prompt hygiene required.
    let denied = reg
        .dispatch(
            "shell",
            serde_json::json!({ "program": "rm", "args": ["-rf", "/"] }),
            &granted,
        )
        .await;
    assert!(denied.is_err());

    Ok(())
}
```

`echo` runs via brush's **carried** builtin even with an empty `PATH` — the
shell runtime is baked in, not borrowed from the host.

## Crates

| Crate | Purpose | Heavy deps |
|---|---|---|
| `agent-bridle-core` | `Tool` trait, `Registry`, `Gate`, `Caveats` re-export, `Sandbox` trait, result envelope | none beyond `anyhow`, `serde`, `serde_json`, `async-trait`, `agent-mesh-protocol` |
| `agent-bridle-tool-shell` | brush-backed confined shell (carried coreutils), `shell` feature | brush-core/builtins/coreutils-builtins, tokio |
| `agent-bridle` | facade re-exporting a ready-to-use registry | — |
| `agent-bridle-mcp` | MCP (Model Context Protocol) stdio server frontend over the registry (binary) | tokio, toml |

## MCP server frontend (`agent-bridle-mcp`)

MCP is the lingua franca of the agent line (DESIGN §4): any MCP client can drive
`agent-bridle-mcp` over stdio and call the **Caveats-confined** Rust tools. It
speaks newline-delimited JSON-RPC 2.0 and handles `initialize`, `tools/list`,
`tools/call`, and `shutdown`/`exit`.

```bash
# Build the binary (shell tool on by default).
cargo build -p agent-bridle-mcp --release
# Binary: target/release/agent-bridle-mcp  (reads/writes JSON-RPC on stdio)
```

### Wiring it into an MCP client

**hermes-thoon** (`mcp_servers:` config):

```yaml
mcp_servers:
  agent-bridle:
    command: /path/to/agent-bridle-mcp
    # The leash for this server's whole session (see "Confinement" below):
    env:
      AGENT_BRIDLE_CAVEATS: '{"fs_read":"all","fs_write":"all","exec":{"only":["git","cargo"]},"net":"all","max_calls":{"at_most":50},"valid_for_generation":"all"}'
```

**Claude Code / `claude mcp add`:**

```bash
claude mcp add agent-bridle \
  --env AGENT_BRIDLE_CAVEATS='{"fs_read":"all","fs_write":"all","exec":{"only":["git"]},"net":"all","max_calls":"unlimited","valid_for_generation":"all"}' \
  -- /path/to/agent-bridle-mcp
```

### The leash: granting Caveats

The session's granted `Caveats` are sourced in this order (first hit wins):

1. **`$AGENT_BRIDLE_CAVEATS`** — a JSON document using the `agent-mesh-protocol`
   `Caveats` serde shape.
2. **`~/.agent-bridle/config.toml`**, a `[caveats]` table (same field/enum shape
   in TOML).
3. **Default `Caveats::top()`** — *unconfined*. The server prints a prominent
   `WARNING: ... running UNCONFINED ...` to stderr in this case, because an
   unconfined leash defeats the purpose of the bridle. Always set (1) or (2) in
   production.

The serde shape matches the Rust type exactly — each string axis is either
`"all"` or `{ "only": [...] }`; `max_calls` is `"unlimited"` or
`{ "at_most": N }`:

```jsonc
// $AGENT_BRIDLE_CAVEATS — JSON
{
  "fs_read": "all",
  "fs_write": "all",
  "exec": { "only": ["echo", "git"] },   // may exec ONLY echo and git
  "net": "all",
  "max_calls": { "at_most": 20 },
  "valid_for_generation": "all"
}
```

```toml
# ~/.agent-bridle/config.toml — TOML
[caveats]
fs_read = "all"
fs_write = "all"
exec = { only = ["echo", "git"] }
net = "all"
max_calls = { at_most = 20 }
valid_for_generation = "all"
```

### Confinement example (restricting `exec`)

Grant a leash that may exec only `echo`, then watch the server enforce it
*through the MCP boundary*:

```bash
export AGENT_BRIDLE_CAVEATS='{"fs_read":"all","fs_write":"all","exec":{"only":["echo"]},"net":"all","max_calls":"unlimited","valid_for_generation":"all"}'

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{"program":"echo","args":["hi"]}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{"program":"rm","args":["-rf","/"]}}}' \
  | agent-bridle-mcp
```

`echo` runs (`isError: false`, stdout `hi`). `rm` is **denied** — the leash
refuses it and the reason comes back as an MCP *tool error*, not a transport
fault:

```json
{"id":3,"jsonrpc":"2.0","result":{"content":[{"text":"denied: exec of \"rm\" is not within the granted authority","type":"text"}],"isError":true}}
```

## Status

This is **P0** plus the **MCP frontend** (DESIGN §4 frontend 2): the core leash,
a confined brush shell, and an `agent-bridle-mcp` stdio JSON-RPC server, with
tests proving the leash *denies* out-of-scope exec, exhausted budgets,
generation mismatch, and path-escape (`..` / symlink) attempts — including a
through-MCP integration test that drives the real binary over stdio and proves
an out-of-scope `tools/call` is denied across the protocol boundary. Landlock
enforcement, the brush exec/open hook, the Python pillars (sidecar + host tools
dir), and web/scm tools are later phases (see `docs/DESIGN.md` §12).

## License

Apache-2.0. `brush` is vendored as a dependency under MIT; its notice is carried
in [`NOTICE`](NOTICE).

[`agent_mesh_protocol::Caveats`]: https://crates.io/crates/agent-mesh-protocol
