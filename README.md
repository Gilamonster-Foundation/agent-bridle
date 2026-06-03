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

## Status

This is **P0**: the core leash + a confined brush shell, with tests proving the
leash *denies* out-of-scope exec, exhausted budgets, generation mismatch, and
path-escape (`..` / symlink) attempts. Landlock enforcement, the brush
exec/open hook, the MCP frontend, the Python pillars, and web/scm tools are
later phases (see `docs/DESIGN.md` §12).

## License

Apache-2.0. `brush` is vendored as a dependency under MIT; its notice is carried
in [`NOTICE`](NOTICE).

[`agent_mesh_protocol::Caveats`]: https://crates.io/crates/agent-mesh-protocol
