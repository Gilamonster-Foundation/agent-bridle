# Status

Kept out of the README because it rots faster than anything else here.

## Landed

**Core leash + MCP frontend** (P0 plus DESIGN §4 frontend 2) — the core
leash, a confined carried Brush shell (with the argv + safe-subset
alternative), and an `agent-bridle-mcp` stdio JSON-RPC server. Tests prove
the leash *denies* out-of-scope exec, exhausted budgets, generation
mismatch, and path-escape (`..` / symlink) attempts, including a
through-MCP integration test that drives the real binary over stdio and
proves an out-of-scope `tools/call` is denied across the protocol
boundary.

**The `net` enforcer** (`agent-bridle-tool-web`, `web` feature) — a
confined `web_fetch` whose host allowlist, SSRF IP screen, per-redirect
re-check, and DNS-rebinding IP pin are unit-tested in isolation and
exercised end-to-end against a localhost mock server (a disallowed host, a
private/loopback address, and a redirect to a disallowed host are all
proven *denied*).

**Native L3 backends, per platform:**

- **Linux** — Landlock `fs_write`/`fs_read` kernel enforcement, direct-exec
  narrowing (still honestly reported `Interceptor` because of the loader
  trampoline), and deny-all TCP on ABI-v4 kernels.
- **macOS** — Seatbelt kernel-confines both filesystem axes, restricted
  exec, and deny-all or loopback-only network scopes.
- **Windows** — the wired AppContainer launcher confines filesystem paths,
  deny-all or loopback-only network scopes, and exec deny-all; non-empty
  exec allowlists remain `Interceptor`.

General remote-host network allowlists retain their documented
proxy/advisory posture.

## Later phases

Stronger Linux exec identity, the Python sidecar/tools-dir pillar, browse,
`web_search`, and scm tools remain later phases (see `docs/DESIGN.md` §12).
