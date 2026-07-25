# agent-bridle

**The capability leash for agent tools.** `agent-bridle` is the shared tool +
capability-enforcement layer for the Gilamonster agent line (newt, gilamonster,
Monty, hermes-thoon). It turns each host's hand-wired, ambient-authority tool
surface into an extensible, **capability-governed registry**.

> **the toolchain** (`git`, `cargo`, `python`, …) = the hands. **`Caveats`** =
> the leash. **bridle** = the enforcer that binds them.

> Governed by the [Steward's Charter](https://github.com/Gilamonster-Foundation/steward-charter).
> agent-bridle realizes the **`writ`** invariant (authority is borrowed, scoped,
> revocable — the `Caveats`/`Gate`). A leash *denial* is a Charter **`refusal`**:
> the draft edge in [`integrations/charter-bridle`](integrations/charter-bridle)
> records each denial into the **`scar`**, so a refusal becomes metabolized memory
> rather than an ephemeral error.

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
attenuation-only, with enforcement minted at a single choke point and
backstopped by an available native L3 backend. Every result discloses the
boundary and per-axis strength actually achieved, so weaker enforcement is
visible rather than overclaimed.

## Usage

```rust
use agent_bridle::registry;
use agent_bridle_core::{Caveats, CountBound, Scope};

fn main() -> anyhow::Result<()> {
    // Must run before constructing an async runtime. This handles both the
    // private sandboxed worker and its carried-command re-exec entrypoint.
    if let Some(code) = agent_bridle::maybe_dispatch() {
        std::process::exit(code);
    }
    tokio::runtime::Runtime::new()?.block_on(async_main())
}

async fn async_main() -> anyhow::Result<()> {
    // Linux/macOS select Brush + bundled coreutils. Targets without its
    // authenticated private transport select the safe-subset shell.
    let reg = registry();

    // No external executable authority; shell builtins can still run.
    let granted = Caveats {
        exec: Scope::only([]),
        max_calls: CountBound::AtMost(2),
        ..Caveats::top()
    };

    // ALLOWED: `echo` is Brush's native builtin, carried with the engine, so it
    // spawns nothing.
    let out = reg
        .dispatch(
            "shell",
            serde_json::json!({ "cmd": "echo hello" }),
            &granted,
        )
        .await?;
    println!("{out}"); // -> { "exit_code": 0, "stdout": "hello\n", ... }

    // DENIED in-band: an external executable has not been granted.
    let denied = reg
        .dispatch(
            "shell",
            serde_json::json!({ "cmd": "./not-granted" }),
            &granted,
        )
        .await?;
    assert_eq!(denied["denied"], true);

    Ok(())
}
```

On Linux and macOS, the default engine is the carried bash-in-Rust
`BrushShellTool`. Each invocation runs in a fresh worker created through the
L3-aware spawn funnel. Its parent-created private socket authenticates the real
parent PID and exact executable image; core supplies the effective caveats in a
take-once envelope. The hidden argv, nonce, and readable challenge are not
authority, and direct worker or `--invoke-bundled` invocation is refused.
`brush_private_control_supported()` lets an embedder make the same
construction-time selection. It is a capability probe, not a security override.
On unsupported targets (currently including Windows), Brush fails closed and
the facade registry advertises the safe-subset `ShellTool` instead.

If a host approves a command based on a prospective enforcement check, it
should use `Registry::dispatch_with_strength_floor(...)` for the actual call.
That stamps the approved minimum into the minted context and its trusted-worker
envelope, so a backend downgrade at execution time is refused.

When the effective caveats engage an available native backend, the worker and
every descendant inherit that boundary; otherwise the result honestly reports
`sandbox_kind: none`. Its L2 command interceptor checks every external spawn
and file open initiated through Brush against the effective `exec`/`fs` leash;
children delegated by an admitted external program (for example, `find -exec`)
do not re-enter that interceptor and rely on any inherited L3 boundary. A
restricted filesystem grant is refused when the platform cannot provide the
required L3 boundary. The `carried-coreutils` feature supplies
bundled `ls`/`cat`/`echo`/`head`/`sort`/`wc` implementations without depending
on host utilities. Brush's native builtins win name conflicts, so `echo`
normally remains Brush's in-process builtin; non-conflicting bundled utilities
use the embedding binary's private `--invoke-bundled <name>` re-exec path. This
is why `maybe_dispatch()` must run before the async runtime is constructed.

For the smaller argv + safe-subset `ShellTool`, disable default features and
enable `shell`; that engine accepts `program` + `args` as well as its restricted
`cmd` grammar.

## Crates

| Crate | Purpose | Heavy deps |
|---|---|---|
| `agent-bridle-core` | `Tool` trait, `Registry`, `Gate`, `Caveats` re-export, `Sandbox` trait, result envelope | none beyond `anyhow`, `serde`, `serde_json`, `async-trait`, `agent-mesh-protocol` |
| `agent-bridle-tool-shell` | carried Brush shell + coreutils by default; optional argv + safe-subset and host-shell engines | brush (default facade), tokio |
| `agent-bridle-tool-web` | confined `web_fetch` (the `net` enforcer), `web` feature | reqwest+rustls, dom_smoothie, htmd, hickory-resolver, url, tokio |
| `agent-bridle` | facade re-exporting a ready-to-use registry | — |
| `agent-bridle-mcp` | MCP (Model Context Protocol) stdio server frontend over the registry (binary) | tokio, toml |

## MCP server frontend (`agent-bridle-mcp`)

MCP is the lingua franca of the agent line (DESIGN §4): any MCP client can drive
`agent-bridle-mcp` over stdio and call the **Caveats-confined** Rust tools. It
speaks newline-delimited JSON-RPC 2.0 and handles `initialize`, `tools/list`,
`tools/call`, and `shutdown`/`exit`.

```bash
# Build the release-equivalent binary: carried Brush/coreutils plus the native
# Landlock, Seatbelt, or AppContainer backend selected for the target OS.
cargo build -p agent-bridle-mcp --release --features os-sandbox
# Binary: target/release/agent-bridle-mcp  (reads/writes JSON-RPC on stdio)
```

A plain default build still carries the worker-local L2 shell interceptor, but
does not compile a native L3 backend. Use `os-sandbox` for production
confinement, or select one of the per-OS features directly.

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
3. **Default: DENY-ALL (fail-closed)** — no grant configured means no authority
   on any axis. Set (1) or (2) to grant authority; an absent grant never becomes
   `Caveats::top()`.

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

Grant no external executable authority. The carried Brush `echo` builtin still
works because it spawns nothing, while an attempted external is refused:

```bash
export AGENT_BRIDLE_CAVEATS='{"fs_read":"all","fs_write":"all","exec":{"only":[]},"net":"all","max_calls":"unlimited","valid_for_generation":"all"}'

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"echo hi"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"shell","arguments":{"cmd":"./not-granted"}}}' \
  | agent-bridle-mcp
```

`echo` runs (`isError: false`, stdout `hi`). The external is **denied** — the
leash refuses it and the reason comes back as an MCP *tool error*, not a
transport fault:

```json
{"id":3,"jsonrpc":"2.0","result":{"content":[{"text":"exec of \"./not-granted\" is not within the granted authority","type":"text"}],"isError":true}}
```

## The `net` enforcer: `web_fetch` (`agent-bridle-tool-web`)

`web_fetch` is the tool that exercises the **`net`** axis of the leash — the
axis no other tool touches (DESIGN §7). It fetches an http(s) URL and returns
the page's main content as markdown, with the `net` Caveat enforced *before the
first request and on every redirect hop*:

1. **Host allowlist, default-deny.** The URL's host must satisfy the effective
   `net` scope (`ToolContext::check_net`).
2. **SSRF block.** The host is DNS-resolved and any private / loopback /
   link-local / unique-local address is **rejected** — `127.0.0.0/8`,
   `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`,
   `100.64.0.0/10` (CGNAT), `::1`, `fc00::/7`, `fe80::/10`, IPv4-mapped forms,
   and more — **unless** that host is explicitly named in the `net` allowlist
   (the deliberate opt-in for a test loopback or a named internal endpoint).
3. **Per-redirect re-check.** Redirects are followed *manually*: every hop's
   host is re-screened by (1) and (2). A 302 to a disallowed or private host is
   denied, never blindly followed.
4. **DNS-rebinding pin.** The connection is pinned to the exact IP that passed
   screening, so a rebind between the check and the connect cannot smuggle
   traffic elsewhere.

The TLS stack is **rustls, not OpenSSL**, so the tool is portable and builds on
Windows with no system OpenSSL. The result `{ url, final_url, status, title,
markdown }` is **untrusted data** — never spliced into a system prompt.

### Usage

```rust
use agent_bridle::registry;            // build with --features web
use agent_bridle_core::{Caveats, CountBound, Scope};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let reg = registry();

    // Confine the net axis to a single host. example.com may be reached;
    // nothing else, and no private/loopback address (it is not opted in).
    let granted = Caveats {
        net: Scope::only(["example.com".to_string()]),
        max_calls: CountBound::AtMost(5),
        ..Caveats::top()
    };

    let out = reg
        .dispatch(
            "web_fetch",
            serde_json::json!({ "url": "https://example.com/" }),
            &granted,
        )
        .await?;
    println!("{}", out["markdown"]); // extracted page content as markdown

    // DENIED: a different host is not in the `net` allowlist.
    let denied = reg
        .dispatch(
            "web_fetch",
            serde_json::json!({ "url": "https://not-allowed.test/" }),
            &granted,
        )
        .await;
    assert!(denied.is_err());

    Ok(())
}
```

### Confinement example (the `net` allowlist, through MCP)

Build the server with the web tool and grant a `net` allowlist of exactly one
host:

```bash
cargo build -p agent-bridle-mcp --features web --release

# net allowlist = only example.com. Note: a private/loopback host would ALSO be
# SSRF-blocked unless you name it here (e.g. "127.0.0.1" for a local test).
export AGENT_BRIDLE_CAVEATS='{"fs_read":"all","fs_write":"all","exec":"all","net":{"only":["example.com"]},"max_calls":"unlimited","valid_for_generation":"all"}'

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web_fetch","arguments":{"url":"https://example.com/"}}}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"web_fetch","arguments":{"url":"http://169.254.169.254/latest/meta-data/"}}}' \
  | agent-bridle-mcp
```

The fetch to `example.com` returns markdown; the cloud-metadata SSRF probe to
`169.254.169.254` is **denied** by the host allowlist (and would be SSRF-blocked
even under `net: "all"`).

## Status

This is **P0** plus the **MCP frontend** (DESIGN §4 frontend 2): the core leash,
a confined carried Brush shell (with the argv + safe-subset alternative), and
an `agent-bridle-mcp` stdio JSON-RPC server, with tests proving the leash
*denies* out-of-scope exec, exhausted budgets, generation mismatch, and
path-escape (`..` / symlink) attempts — including a through-MCP integration test
that drives the real binary over stdio and proves an out-of-scope `tools/call`
is denied across the protocol boundary.

The **`net` enforcer** (`agent-bridle-tool-web`, `web` feature) is also landed:
a confined `web_fetch` whose host allowlist, SSRF IP screen, per-redirect
re-check, and DNS-rebinding IP pin are unit-tested in isolation and exercised
end-to-end against a localhost mock server (a disallowed host, a private/loopback
address, and a redirect to a disallowed host are all proven *denied*).

Landlock `fs_write`/`fs_read` kernel enforcement is landed on Linux, along with
direct-exec narrowing (still honestly reported `Interceptor` because of the
loader trampoline) and deny-all TCP on ABI-v4 kernels. On macOS, Seatbelt
kernel-confines both filesystem axes, restricted exec, and deny-all or
loopback-only network scopes. On Windows, the wired AppContainer launcher
confines filesystem paths, deny-all or loopback-only network scopes, and exec
deny-all; non-empty exec allowlists remain `Interceptor`. General remote-host
network allowlists retain their documented proxy/advisory posture. Stronger
Linux exec identity, the Python sidecar/tools-dir pillar, browse,
`web_search`, and scm tools remain later phases (see `docs/DESIGN.md` §12).

## License

Apache-2.0 (see [`LICENSE`](LICENSE)). The carried Brush dependencies are MIT;
their notices are carried in [`NOTICE`](NOTICE).

[`agent_mesh_protocol::Caveats`]: https://crates.io/crates/agent-mesh-protocol
